"""Kullanıcı yönetimi endpoint'leri (Faz 08).

Gereksinimler (phases/08: "RBAC ve audit"; Faz 07 kapanış notu: "görev
ayrımı için ikinci admin eklemek şu an DB seviyesinde — Faz 08 kullanıcı
yönetimi"):

- GET   /users                    (admin)    → kullanıcı listesi
- POST  /users                    (admin)    → kullanıcı oluştur (201)
- PATCH /users/{user_id}          (admin)    → rol / aktiflik güncelle
- POST  /users/me/password        (kimlikli) → kendi parolasını değiştir
- POST  /users/{user_id}/password (admin)    → başkasının parolasını sıfırla

ROUTE SIRASI (kritik): self_router ("me" literal ucu) router.py içinde
admin router'dan ÖNCE dahil edilir; aksi halde POST /users/me/password
istegi {user_id} deseniyle eşleşir ve UUID çözümlemesi hata döner.

Güvenlik davranışları:
- Yönetim uçları admin (router düzeyi dependency — atlama hatası yok);
  /users/me/password her kimlikli kullanıcıya açıktır (önbilgi doğrulamalı).
- Parola değeri HİÇBİR yanıtta/audit'te/logda yer almaz; yalnızca argon2id
  hash saklanır (AGENTS.md §3, §6).
- Parola politikası: settings.user_password_min_length (varsayılan 12).
- Kilitleme korumaları (409):
  * kendi hesabını devre dışı bırakamaz (yanlışlıkla self-lock)
  * SON aktif admin'in rolü düşürülemez / hesabı kapatılamaz
  * admin ucuyla kendi parolası sıfırlanamaz (self /users/me/password)
- Audit: user.created / user.updated / user.password_changed /
  user.password_reset (parola değeri YOK; yapısal detay).
- Rol değişimi anında etkin: yetki kararı her istekte DB'den okunur
  (deps.get_current_user); eski token'daki rol claim'i yetki VERMEZ.

Not: kullanıcı SİLME endpoint'i bilinçli olarak YOKTUR — is_active=false
tercih edilir (audit izi + FK geçmişi korunur; AGENTS.md §2 öncelik 2).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser, SessionDep, require_role
from app.api.v1.schemas import (
    PasswordChangeRequest,
    PasswordChangeResponse,
    PasswordResetRequest,
    UserCreateRequest,
    UserItem,
    UserListResponse,
    UserMutationResponse,
    UserUpdateRequest,
)
from app.core.config import Settings
from app.core.logging import get_logger
from app.models.user import ROLE_ADMIN, User
from app.services.security import (
    AuditAction,
    AuditService,
    hash_password,
    verify_password,
)

router = APIRouter(tags=["users"], dependencies=[Depends(require_role(ROLE_ADMIN))])
# /users/me/password: her kimlikli kullanıcı (admin dependency'siz router).
self_router = APIRouter(tags=["users"])
logger = get_logger(__name__)


async def _get_user_or_none(session: AsyncSession, user_id: str) -> User | None:
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        return None
    stmt = select(User).where(User.id == user_uuid)
    return (await session.scalars(stmt)).first()


async def _count_active_admins(session: AsyncSession) -> int:
    stmt = (
        select(func.count())
        .select_from(User)
        .where(User.role == ROLE_ADMIN, User.is_active.is_(True))
    )
    return int((await session.scalars(stmt)).one())


def _reject(code: str, message: str, status: int = 409) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": message, "code": code})


def _password_too_short(settings: Settings, password: str) -> bool:
    return len(password) < settings.user_password_min_length


@router.get("/users", response_model=UserListResponse)
async def list_users(session: SessionDep) -> UserListResponse:
    """Kullanıcı listesi (admin). Parola hash'i dönmez (şemada alan yok)."""
    rows = (await session.scalars(select(User).order_by(User.created_at.asc()))).all()
    items = [UserItem.model_validate(u) for u in rows]
    return UserListResponse(items=items, total=len(items))


@router.post("/users", response_model=UserMutationResponse, status_code=201)
async def create_user(
    payload: UserCreateRequest,
    request: Request,
    session: SessionDep,
    current_user: CurrentUser,
) -> UserMutationResponse | JSONResponse:
    """Kullanıcı oluştur (admin)."""
    settings: Settings = request.app.state.settings
    audit = AuditService(session)

    if _password_too_short(settings, payload.password):
        return _reject(
            "weak_password",
            f"Parola en az {settings.user_password_min_length} karakter olmalıdır.",
            status=422,
        )

    existing = (
        await session.scalars(select(User).where(User.username == payload.username))
    ).first()
    if existing is not None:
        return _reject("username_taken", "Bu kullanıcı adı zaten kullanımda.")

    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:
        # Eşzamanlı çift create yarışı: SELECT-sonra-INSERT penceresinde
        # UNIQUE çarpar → 500 yerine idempotent 409 (Faz 07 F3 kalıbı).
        await session.rollback()
        return _reject("username_taken", "Bu kullanıcı adı zaten kullanımda.")
    await session.refresh(user)

    await audit.record(
        action=AuditAction.USER_CREATED,
        actor=current_user.username,
        actor_user_id=current_user.id,
        resource=f"user:{user.username}",
        detail={"target_id": str(user.id), "role": user.role},
    )
    return UserMutationResponse(user=UserItem.model_validate(user))


@router.patch("/users/{user_id}", response_model=UserMutationResponse)
async def update_user(
    user_id: str,
    payload: UserUpdateRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> UserMutationResponse | JSONResponse:
    """Rol/aktiflik güncelle (admin). Son-admin ve self-lock korumalı."""
    if payload.role is None and payload.is_active is None:
        return _reject("no_changes", "Güncellenecek alan verilmedi.", status=422)

    user = await _get_user_or_none(session, user_id)
    if user is None:
        return _reject("user_not_found", "Kullanıcı bulunamadı.", status=404)

    audit = AuditService(session)
    role_changed = payload.role is not None and payload.role != user.role
    deactivating = payload.is_active is False and user.is_active

    # Kural 1: kendi hesabını devre dışı bırakma
    if deactivating and str(user.id) == current_user.id:
        return _reject(
            "cannot_disable_self",
            "Kendi hesabınızı devre dışı bırakamazsınız; başka bir admin "
            "tarafından kapatılabilir.",
        )

    # Kural 2: son aktif admin kaybı (rol düşürme veya kapatma)
    if user.role == ROLE_ADMIN and (role_changed or deactivating):
        active_admins = await _count_active_admins(session)
        if user.is_active and active_admins <= 1:
            return _reject(
                "last_active_admin",
                "Son aktif admin'in rolü düşürülemez veya hesabı kapatılamaz. "
                "Önce başka bir admin ekleyin.",
            )

    detail: dict[str, object] = {}
    if payload.role is not None:
        detail["role_from"] = user.role
        detail["role_to"] = payload.role
        user.role = payload.role
    if payload.is_active is not None:
        detail["is_active_to"] = payload.is_active
        user.is_active = payload.is_active

    await session.commit()
    await session.refresh(user)

    await audit.record(
        action=AuditAction.USER_UPDATED,
        actor=current_user.username,
        actor_user_id=current_user.id,
        resource=f"user:{user.username}",
        detail=detail,
    )
    return UserMutationResponse(user=UserItem.model_validate(user))


@self_router.post("/users/me/password", response_model=PasswordChangeResponse)
async def change_my_password(
    payload: PasswordChangeRequest,
    request: Request,
    session: SessionDep,
    current_user: CurrentUser,
) -> PasswordChangeResponse | JSONResponse:
    """Kendi parolasını değiştir (önbilgi doğrulamalı; tüm roller)."""
    settings: Settings = request.app.state.settings
    db_user = await _get_user_or_none(session, current_user.id)
    if db_user is None:
        return _reject("user_not_found", "Kullanıcı bulunamadı.", status=404)
    if not verify_password(db_user.password_hash, payload.current_password):
        return _reject("wrong_current_password", "Mevcut parola hatalı.", status=400)
    if verify_password(db_user.password_hash, payload.new_password):
        # Faz 08 bulgu kapatma (8-test F2): aynı parola "rotasyon yapıldı"
        # yanılsamasını önler; değişiklik reddedilir.
        return _reject(
            "same_password",
            "Yeni parola mevcut parola ile aynı olamaz.",
            status=422,
        )
    if _password_too_short(settings, payload.new_password):
        return _reject(
            "weak_password",
            f"Parola en az {settings.user_password_min_length} karakter olmalıdır.",
            status=422,
        )
    db_user.password_hash = hash_password(payload.new_password)
    await session.commit()
    await AuditService(session).record(
        action=AuditAction.USER_PASSWORD_CHANGED,
        actor=db_user.username,
        actor_user_id=db_user.id,
        resource=f"user:{db_user.username}",
        detail={"mechanism": "self_change"},
    )
    return PasswordChangeResponse(result="updated")


@router.post("/users/{user_id}/password", response_model=PasswordChangeResponse)
async def reset_user_password(
    user_id: str,
    payload: PasswordResetRequest,
    request: Request,
    session: SessionDep,
    current_user: CurrentUser,
) -> PasswordChangeResponse | JSONResponse:
    """Başka kullanıcının parolasını sıfırla (admin).

    Self-sıfırlama bu uçta KAPALI: kendi parolası /users/me/password ile
    önbilgi doğrulaması yapılarak değiştirilir (token çalınsa bile parola
    değişimi mevcut parolayı bilmeyen saldırgana kapalı kalır).
    """
    settings: Settings = request.app.state.settings
    if _password_too_short(settings, payload.new_password):
        return _reject(
            "weak_password",
            f"Parola en az {settings.user_password_min_length} karakter olmalıdır.",
            status=422,
        )

    user = await _get_user_or_none(session, user_id)
    if user is None:
        return _reject("user_not_found", "Kullanıcı bulunamadı.", status=404)
    if str(user.id) == current_user.id:
        return _reject(
            "use_self_endpoint",
            "Kendi parolanızı bu uçtan sıfırlayamazsınız; "
            "/users/me/password uçunu kullanın.",
        )
    if verify_password(user.password_hash, payload.new_password):
        # Faz 08 bulgu kapatma (8-test F2): admin reset de aynı-parola reddi.
        return _reject(
            "same_password",
            "Yeni parola kullanıcının mevcut parolası ile aynı olamaz.",
            status=422,
        )

    user.password_hash = hash_password(payload.new_password)
    await session.commit()
    await AuditService(session).record(
        action=AuditAction.USER_PASSWORD_RESET,
        actor=current_user.username,
        actor_user_id=current_user.id,
        resource=f"user:{user.username}",
        detail={"target_id": str(user.id), "mechanism": "admin_reset"},
    )
    return PasswordChangeResponse(result="updated")
