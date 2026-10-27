"""Kullanıcı doğrulama, token ihraç ve bootstrap mantığı (Faz 05).

Sözleşmeler:
- authenticate_user(): kullanıcı adı küçük harfe normalize edilir; kullanıcı
  yoksa / parola yanlışsa / kullanıcı pasifse AYRIŞTIRILMAZ genel None
  döner (kullanıcı sayım saldırısı frenlenir; ayırt etme log tarafında
  yapılır ama istemci mesajına sızmaz).
- issue_token_pair(): DB'den doğrulanmış kullanıcıya token çifti üretir;
  rol claim'i DB'deki güncel rolden alınır.
- bootstrap_admin_if_empty(): users boşsa ADMIN_BOOTSTRAP_PASSWORD ile
  'admin' rolünde kullanıcı oluşturur. Parola değerleri ASLA log/audit'e
  yazılmaz (yalnızca kullanıcı adı ve eylem adı).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.user import ROLE_ADMIN, User
from app.services.security.passwords import hash_password, verify_password
from app.services.security.tokens import (
    TokenPair,
    create_access_token,
    create_refresh_token,
)

logger = get_logger(__name__)

# Kullanıcı yokken zaman profilini korumak için SAHTE parolanın argon2id
# hash'i (modül yüklenirken GERÇEK KDF ile üretilir: bilinmeyen kullanıcı
# denemeleri de gerçek hash maliyeti öder — kullanıcı sayım/timing
# saldırısı freni. Değer hiçbir gerçek kullanıcıya ait değildir.)
_DECOY_HASH = hash_password("decoy-password-faz05-timing-guard")


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """Doğrulanmış kullanıcı görüntüsü (API katmanına döner)."""

    id: str
    username: str
    role: str
    is_active: bool


class AuthError(Exception):
    """Kimlik doğrulama akışı hatası (API 401'e çevirir)."""


def _normalize_username(username: str) -> str:
    return username.strip().lower()


async def authenticate_user(
    session: AsyncSession, *, username: str, password: str
) -> AuthenticatedUser | None:
    """Kullanıcı adı + parola doğrulaması; başarısızlıkta None döner.

    Faz 08: is_active=false kullanıcı için de None döner — devre dışı
    bırakılan hesap YENİ token edinemez (mevcut token'lar zaten her istekte
    DB aktiflik kontrolüyle düşer; iki katman savunma derinliğidir).
    """
    stmt = select(User).where(User.username == _normalize_username(username))
    user: User | None = (await session.scalars(stmt)).first()
    if user is None:
        # Aynı zaman profilini korumak için sahte doğrulama yapılır
        # (kullanıcı yokken yanıt belirgin hızlı gelmez — sayım freni).
        verify_password(_DECOY_HASH, password)
        return None
    if not verify_password(user.password_hash, password):
        return None
    if not user.is_active:
        # Doğru parola olsa bile pasif hesap giremez (genel None: kullanıcı
        # durumu ayrımı istemciye sızmaz — GENERIC_LOGIN_FAILED mesajı).
        return None
    return AuthenticatedUser(
        id=str(user.id), username=user.username, role=user.role, is_active=user.is_active
    )


async def issue_token_pair(
    session: AsyncSession,
    *,
    secret: str,
    algorithm: str,
    access_ttl_minutes: int,
    refresh_ttl_minutes: int,
    user: AuthenticatedUser,
) -> TokenPair:
    """Doğrulanmış kullanıcı için access+refresh çifti üretir."""
    access = create_access_token(
        secret=secret,
        algorithm=algorithm,
        subject=user.id,
        username=user.username,
        role=user.role,
        ttl_minutes=access_ttl_minutes,
    )
    refresh = create_refresh_token(
        secret=secret,
        algorithm=algorithm,
        subject=user.id,
        username=user.username,
        role=user.role,
        ttl_minutes=refresh_ttl_minutes,
    )
    # Başarılı girişte last_login güncellenir (users üzerinde izinli UPDATE).
    stmt = select(User).where(User.id == uuid.UUID(user.id))
    db_user: User | None = (await session.scalars(stmt)).first()
    if db_user is not None:
        db_user.last_login_at = datetime.now(UTC)
        await session.commit()
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=access_ttl_minutes * 60,
    )


async def load_active_user(
    session: AsyncSession, *, user_id: str
) -> AuthenticatedUser | None:
    """Token konusundan GÜNCEL kullanıcıyı yükler (yetki kararı burada).

    Kullanıcı yoksa veya is_active=false ise None döner — sahte/eski
    token ile panel erişimi kapanır (phases/05: "yetkisiz kullanıcı bir
    alert'e doğrudan ID ile de erişememeli").
    """
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        return None
    stmt = select(User).where(User.id == user_uuid)
    user: User | None = (await session.scalars(stmt)).first()
    if user is None or not user.is_active:
        return None
    return AuthenticatedUser(
        id=str(user.id), username=user.username, role=user.role, is_active=user.is_active
    )


async def bootstrap_admin_if_empty(
    session: AsyncSession,
    *,
    username: str,
    password: str | None,
) -> bool:
    """users boşsa ilk admin kullanıcısını oluşturur; oluştuysa True döner.

    - Parola None ise hiçbir şey yapılmaz (False döner; çağıran uyarı loglar).
    - Parola ASLA log/audit detayına yazılmaz.
    """
    total: int = (await session.scalars(select(func.count()).select_from(User))).one()
    if total > 0:
        return False
    if not password:
        logger.warning(
            "bootstrap_skipped_no_password",
            hint="ADMIN_BOOTSTRAP_PASSWORD ayarlanmadan ilk kurulum: panel girişi kapalı kalır.",
        )
        return False
    admin = User(
        username=_normalize_username(username),
        password_hash=hash_password(password),
        role=ROLE_ADMIN,
        is_active=True,
    )
    session.add(admin)
    await session.commit()
    logger.info("bootstrap_admin_created", username=admin.username)
    return True
