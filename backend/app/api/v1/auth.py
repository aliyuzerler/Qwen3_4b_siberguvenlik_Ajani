"""Kimlik doğrulama endpoint'leri (Faz 05).

- POST /auth/login  : kullanıcı adı + parola → token çifti (rate limitli)
- POST /auth/refresh: refresh token → yeni token çifti (rate limitli)
- GET  /auth/me     : güncel kullanıcı (access token gerekir)

Güvenlik davranışları:
- Hatalı giriş mesajı TEK BİÇİMDİR (kullanıcı/parola ayrımı sızdırılmaz).
- Frenlenen istek 429 + Retry-After alır ve audit'e yazılır.
- Audit: login.success / login.failed / login.rate_limited / refresh.*.
  Parola değeri ASLA kaydedilmez.
- CSRF notu: kimlik Bearer başlığıyla taşınır (cookie oturumu YOK); bu
  modelde CSRF vektörü uygulanmaz — karar ve gerekçe
  docs/phase-05-verification.md içinde belgelenmiştir.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.api.v1.deps import CurrentUser, SessionDep
from app.api.v1.schemas import (
    LoginRequest,
    MeResponse,
    RefreshRequest,
    TokenResponse,
)
from app.core.config import Settings
from app.core.logging import get_logger
from app.services.security import (
    AuditAction,
    AuditService,
    TokenError,
    authenticate_user,
    decode_token,
    issue_token_pair,
    load_active_user,
)
from app.services.security.tokens import TOKEN_TYPE_REFRESH

router = APIRouter(tags=["auth"])
logger = get_logger(__name__)

GENERIC_LOGIN_FAILED = "Kullanıcı adı veya parola hatalı."


def _client_ip(request: Request) -> str | None:
    """İstemci IP'si (proxy arkasında X-Forwarded-For ilk değer).

    Compose dağıtımında backend doğrudan erişilir; XFF yalnızca varsa
    kullanılır ve değer doğrulanmadan (uzunluk sınırlı) audit'e yazılır.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        return first[:64] or None
    if request.client is not None and request.client.host:
        return request.client.host[:64]
    return None


def _request_id(request: Request) -> str | None:
    return request.headers.get("X-Request-ID")


@router.post("/auth/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest, request: Request, session: SessionDep
) -> TokenResponse | JSONResponse:
    """Giriş: rate limit → doğrulama → token çifti + audit."""
    settings: Settings = request.app.state.settings
    limiter = request.app.state.auth_rate_limiter
    audit = AuditService(session)
    ip = _client_ip(request)

    decision = await limiter.check(f"login:{ip or 'bilinmeyen'}")
    if not decision.allowed:
        await audit.record(
            action=AuditAction.LOGIN_RATE_LIMITED,
            actor=payload.username[:64],
            client_ip=ip,
            request_id=_request_id(request),
            detail={"retry_after": decision.retry_after_seconds},
        )
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(decision.retry_after_seconds)},
            content={"detail": "Çok fazla deneme. Lütfen birazdan tekrar deneyin."},
        )

    user = await authenticate_user(
        session, username=payload.username, password=payload.password
    )
    if user is None:
        await audit.record(
            action=AuditAction.LOGIN_FAILED,
            actor=payload.username[:64],
            client_ip=ip,
            request_id=_request_id(request),
        )
        return JSONResponse(
            status_code=401,
            content={"detail": GENERIC_LOGIN_FAILED},
        )

    token_pair = await issue_token_pair(
        session,
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        access_ttl_minutes=settings.jwt_access_ttl_minutes,
        refresh_ttl_minutes=settings.jwt_refresh_ttl_minutes,
        user=user,
    )
    await audit.record(
        action=AuditAction.LOGIN_SUCCESS,
        actor=user.username,
        actor_user_id=user.id,
        client_ip=ip,
        request_id=_request_id(request),
    )
    return TokenResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
        expires_in=token_pair.expires_in,
    )


@router.post("/auth/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest, request: Request, session: SessionDep
) -> TokenResponse | JSONResponse:
    """Refresh token → yeni token çifti (rotation).

    Eski access token'ın kalan ömrü boyunca geçerliliği devam eder
    (stateless JWT). ANINDA İPTAL kararı (Faz 08): jti denylist yerine
    DB aktiflik kontrolü tercih edildi — load_active_user her istekte
    users.is_active okur; kullanıcı devre dışı bırakıldığında tüm access
    ve refresh token'ları bir sonraki istekte değersizleşir (denylist
    altyapısına gerek kalmaz; kararı: phase-08-verification.md).
    """
    settings: Settings = request.app.state.settings
    limiter = request.app.state.auth_rate_limiter
    audit = AuditService(session)
    ip = _client_ip(request)

    decision = await limiter.check(f"refresh:{ip or 'bilinmeyen'}")
    if not decision.allowed:
        await audit.record(
            action=AuditAction.REFRESH_FAILED,
            actor=None,
            client_ip=ip,
            request_id=_request_id(request),
            detail={"reason": "rate_limited"},
        )
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(decision.retry_after_seconds)},
            content={"detail": "Çok fazla deneme. Lütfen birazdan tekrar deneyin."},
        )

    try:
        claims = decode_token(
            payload.refresh_token,
            secret=settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
            expected_type=TOKEN_TYPE_REFRESH,
        )
    except TokenError:
        await audit.record(
            action=AuditAction.REFRESH_FAILED,
            actor=None,
            client_ip=ip,
            request_id=_request_id(request),
            detail={"reason": "invalid_token"},
        )
        return JSONResponse(
            status_code=401,
            content={"detail": "Oturum geçersiz. Lütfen yeniden giriş yapın."},
        )

    user = await load_active_user(session, user_id=claims.subject)
    if user is None:
        await audit.record(
            action=AuditAction.REFRESH_FAILED,
            actor=claims.username[:64],
            client_ip=ip,
            request_id=_request_id(request),
            detail={"reason": "user_missing_or_inactive"},
        )
        return JSONResponse(
            status_code=401,
            content={"detail": "Oturum geçersiz. Lütfen yeniden giriş yapın."},
        )

    token_pair = await issue_token_pair(
        session,
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        access_ttl_minutes=settings.jwt_access_ttl_minutes,
        refresh_ttl_minutes=settings.jwt_refresh_ttl_minutes,
        user=user,
    )
    await audit.record(
        action=AuditAction.REFRESH_SUCCESS,
        actor=user.username,
        actor_user_id=user.id,
        client_ip=ip,
        request_id=_request_id(request),
    )
    return TokenResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
        expires_in=token_pair.expires_in,
    )


@router.get("/auth/me", response_model=MeResponse)
async def me(current_user: CurrentUser) -> MeResponse:
    """Güncel kullanıcı (panel başlık çubuğu ve rol gizlemesi için)."""
    return MeResponse(
        id=current_user.id, username=current_user.username, role=current_user.role
    )
