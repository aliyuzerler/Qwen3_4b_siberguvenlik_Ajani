"""FastAPI dependency'leri — kimlik doğrulama ve RBAC (Faz 05).

Yetki modeli (server-side authorization, AGENTS.md §4):
- Yetki kararı YALNIZCA sunucuda verilir: Bearer access token → imza/tip
  doğrulaması → DB'den GÜNCEL kullanıcı (is_active + rol) → rol kontrolü.
- Frontend rol gizleme yalnızca kozmetiktir; 403 kararı burada doğar.
- Yetkisiz istem: 401 (kimlik yok/geçersiz) veya 403 (kimlik var, yetki
  yok) — ikisi de gövdede genel mesaj taşır, iç detay sızmaz.

Kullanıcıya ait alert erişimi: bu sistem tek kiracılıdır (Faz 00 kararı);
viewer/analyses tüm olayları görebilir. "Kullanıcı bir alert'i görme
yetkisine sahip değilse doğrudan ID ile de alamamalı" gereksinimi şöyle
karşılanır: geçersiz/pasif token ile ID bilinse bile 401 döner
(test: test_admin_role_from_token_cannot_bypass_inactive_user).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_session
from app.services.security import (
    AuthenticatedUser,
    TokenError,
    decode_token,
    load_active_user,
)
from app.services.security.tokens import TOKEN_TYPE_ACCESS

# auto_error=False: 401 mesajını kendimiz üretiriz (FastAPI varsayılanı 403 döner).
_bearer = HTTPBearer(auto_error=False, description="access_token (Bearer)")

SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def get_current_user(
    request: Request,
    session: SessionDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
) -> AuthenticatedUser:
    """Bearer access token'ı doğrular ve güncel kullanıcıyı döndürür.

    - Başlık yok / biçim bozuk / imza hatalı / tip access değil → 401
    - Kullanıcı DB'de yok veya is_active=false → 401 (pasif kullanıcının
      elindeki token anında değersizleşir)
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=401,
            detail="Kimlik doğrulaması gerekli.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    settings = request.app.state.settings
    try:
        claims = decode_token(
            credentials.credentials,
            secret=settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
            expected_type=TOKEN_TYPE_ACCESS,
        )
    except TokenError as exc:
        raise HTTPException(
            status_code=401,
            detail="Oturum geçersiz veya süresi dolmuş.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = await load_active_user(session, user_id=claims.subject)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Oturum geçersiz veya süresi dolmuş.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    request.state.user = user
    return user


CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]


def require_role(
    *allowed_roles: str,
) -> Callable[[AuthenticatedUser], Awaitable[AuthenticatedUser]]:
    """Rol kısıtı dependency fabrikası (örn. require_role(ROLE_ADMIN)).

    Boş allowed_roles programlama hatasıdır (tüm rolleri açık bırakmak
    istenirse endpoint dependency'siz bırakılır; sessiz genişlik yok).
    """

    if not allowed_roles:
        raise ValueError("require_role en az bir rol ister.")

    async def _checker(current_user: CurrentUser) -> AuthenticatedUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail="Bu işlem için gerekli yetkiniz yok.",
            )
        return current_user

    return _checker
