"""JWT access/refresh token üretimi ve doğrulaması (Faz 05).

Güvenlik notları (AGENTS.md §4):
- Yalnızca HS256 (settings.jwt_algorithm ile senkron; başka algoritma
  kabul edilmez — "alg" confusion saldırısı decode tarafında kapanır:
  PyJWT'ye algoritma AÇIKÇA verilir, header'dan okunmaz).
- access token kısa ömürlüdür (varsayılan 15 dk); refresh token uzun ama
  yalnızca /auth/refresh'te geçerlidir (type claim'i ayrımı; refresh token
  ile API çağrısı 401 verir).
- Claims: sub (kullanıcı UUID), username, role, typ, iat, exp, jti.
  Yetki kararı token'daki rolden VERİLMEZ — DB'den güncel rol/is_active
  okunur (services/security/service.py sözleşmesi).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import jwt

from app.core.logging import get_logger

logger = get_logger(__name__)

TOKEN_TYPE_ACCESS: TokenType = "access"  # noqa: S105  # token tipi etiketi
TOKEN_TYPE_REFRESH: TokenType = "refresh"  # noqa: S105  # token tipi etiketi
TokenType = Literal["access", "refresh"]


class TokenError(Exception):
    """Token üretimi/doğrulaması hatası (imza, süre, tip, biçim)."""


@dataclass(frozen=True, slots=True)
class TokenPair:
    """Giriş/refresh yanıtında döndürülen çift."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105  # HTTP auth şeması adı
    expires_in: int = 0  # access token kalan saniye (istek anı)


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """Doğrulanmış token içerği (yalnızca güvenli alanlar)."""

    subject: str
    username: str
    role: str
    token_type: str
    expires_at: datetime
    jti: str


def _issue(
    *,
    secret: str,
    algorithm: str,
    token_type: TokenType,
    subject: str,
    username: str,
    role: str,
    ttl_minutes: int,
) -> str:
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "username": username,
        "role": role,
        "typ": token_type,
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


def create_access_token(
    *, secret: str, algorithm: str, subject: str, username: str, role: str, ttl_minutes: int
) -> str:
    """Kısa ömürlü API erişim token'ı üretir."""
    return _issue(
        secret=secret,
        algorithm=algorithm,
        token_type=TOKEN_TYPE_ACCESS,
        subject=subject,
        username=username,
        role=role,
        ttl_minutes=ttl_minutes,
    )


def create_refresh_token(
    *, secret: str, algorithm: str, subject: str, username: str, role: str, ttl_minutes: int
) -> str:
    """Yalnızca /auth/refresh'te geçerli uzun ömürlü token üretir."""
    return _issue(
        secret=secret,
        algorithm=algorithm,
        token_type=TOKEN_TYPE_REFRESH,
        subject=subject,
        username=username,
        role=role,
        ttl_minutes=ttl_minutes,
    )


def decode_token(
    token: str, *, secret: str, algorithm: str, expected_type: TokenType
) -> TokenClaims:
    """Token'ı doğrular; tip/bekleme uymazsa TokenError fırlatır.

    - İmza/süre doğrulaması PyJWT'de (alg AÇIKÇA verilir).
    - typ claim beklenen tip değilse reddedilir (refresh ile API erişimi
      ve access ile refresh akışı kapatılır).
    - Alan tipleri katı: sub/username/role string değilse reddedilir.
    """
    try:
        payload: dict[str, Any] = jwt.decode(
            token, secret, algorithms=[algorithm], options={"require": ["exp", "sub", "typ"]}
        )
    except jwt.PyJWTError as exc:
        # Hata ayrıntısı günlüğe yazılır ama istemciye genel mesaj döner (api katmanı).
        logger.info("token_rejected", reason=type(exc).__name__)
        raise TokenError("token geçersiz") from exc

    token_type = payload.get("typ")
    if token_type != expected_type:
        raise TokenError("token tipi uyuşmuyor")

    subject = payload.get("sub")
    username = payload.get("username")
    role = payload.get("role")
    if not isinstance(subject, str) or not subject:
        raise TokenError("sub eksik")
    if not isinstance(username, str) or not username:
        raise TokenError("username eksik")
    if not isinstance(role, str) or not role:
        raise TokenError("role eksik")

    exp = payload.get("exp")
    expires_at = (
        datetime.fromtimestamp(exp, tz=UTC) if isinstance(exp, (int, float)) else datetime.now(UTC)
    )
    jti_value = payload.get("jti")
    return TokenClaims(
        subject=subject,
        username=username,
        role=role,
        token_type=str(token_type),
        expires_at=expires_at,
        jti=str(jti_value) if isinstance(jti_value, str) else "",
    )
