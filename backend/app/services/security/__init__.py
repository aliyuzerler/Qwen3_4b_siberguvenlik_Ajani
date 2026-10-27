"""Panel güvenlik servisi (Faz 05; Faz 08 paylaşımlı fren + kullanıcı yönetimi).

Paket içeriği:
- passwords : argon2id hash/verify (parola düz metin asla saklanmaz)
- tokens    : JWT access/refresh üretimi + doğrulaması (PyJWT, HS256)
- rate_limit: bellek içi kayan pencere freni + async sözleşme (Faz 08)
- db_rate_limit: paylaşımlı (DB tabanlı) sabit pencere freni (Faz 08;
  RATE_LIMIT_BACKEND=database iken çok prosesli dağıtım için)
- audit     : append-only audit kayıt servisi (AGENTS.md §4)
- service   : kullanıcı doğrulama + bootstrap mantığı

Tasarım kararları:
- Token'da rol TAŞINIR ama yetki kararı verirken DB'deki güncel rol ve
  is_active durumu okunur (get_current_user) — devre dışı bırakılan
  kullanıcının token'ı anında geçersizleşir (JWT kalıntı yetki riski kapanır;
  Faz 08 kararı: jti denylist GEREKMEZ — kullanıcıyı devre dışı bırakmak
  tüm oturumlarını anında düşürür; refresh de DB aktiflik kontrolünden geçer).
- Rate limit: varsayılan bellek içi (tek proses); çok prosesli/çok düğümlü
  dağıtımda RATE_LIMIT_BACKEND=database → paylaşımlı DB sayacı (Faz 08).
"""

from __future__ import annotations

from app.services.security.audit import AuditAction, AuditService
from app.services.security.db_rate_limit import DatabaseRateLimiter
from app.services.security.passwords import hash_password, verify_password
from app.services.security.rate_limit import (
    MemoryRateLimiter,
    RateLimitDecision,
    RateLimiter,
)
from app.services.security.service import (
    AuthenticatedUser,
    AuthError,
    authenticate_user,
    bootstrap_admin_if_empty,
    issue_token_pair,
    load_active_user,
)
from app.services.security.tokens import (
    TokenError,
    TokenPair,
    create_access_token,
    create_refresh_token,
    decode_token,
)

__all__ = [
    "AuditAction",
    "AuditService",
    "AuthError",
    "AuthenticatedUser",
    "DatabaseRateLimiter",
    "MemoryRateLimiter",
    "RateLimiter",
    "RateLimitDecision",
    "TokenError",
    "TokenPair",
    "authenticate_user",
    "bootstrap_admin_if_empty",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "hash_password",
    "issue_token_pair",
    "load_active_user",
    "verify_password",
]
