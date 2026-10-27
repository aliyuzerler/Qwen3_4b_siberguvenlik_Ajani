"""users tablosu ORM modeli (Faz 05 — panel auth/RBAC).

Gereksinimler (phases/05-security-dashboard.md, AGENTS.md §4):
- "Auth, RBAC ve server-side authorization" → kullanıcı kaydı + rol alanı
  sunucu tarafında zorunlu kılınır (API dependency'leri; frontend yalnızca
  kozmetik gizleme yapar, yetki kararı VERMEZ).
- Roller: viewer | analyst | admin (Faz 00 kararı: üç rol; proje sahibi admin).
- Parola ASLA düz metin saklanmaz: argon2id hash (services/security/passwords).
- Parola alanı bu modelde YOKTUR — yalnızca password_hash tutulur; API
  şemaları da parola değerini hiçbir yanıtta geri dönmez.

Erişim yetkileri (belgelenmiş; compose'da uygulanan kullanıcı):
- Uygulama DB kullanıcısı: SELECT/INSERT/UPDATE(users.last_login_at,
  users.is_active). DELETE kodda YOKTUR (kullanıcı silme bu fazda yok;
  is_active=false ile devre dışı bırakma tercih edilir — audit izi korunur).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, CheckConstraint, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.event import UTCDateTime

# Rol değerleri (CHECK kısıtıyla da korunur)
ROLE_VIEWER = "viewer"
ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"
ALL_ROLES = (ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMIN)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class User(Base):
    """Panel kullanıcısı (RBAC öznesi)."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "role IN ('viewer', 'analyst', 'admin')", name="ck_users_role"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    # Kullanıcı adı küçük harfe normalize edilerek saklanır (login de aynı
    # normalizasyonu uygular; büyük/küçük harf duyarlılığı yoktur).
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default=ROLE_VIEWER)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=_utcnow
    )
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover — debug kolaylığı
        return f"User(id={self.id!s}, username={self.username!r}, role={self.role!r})"
