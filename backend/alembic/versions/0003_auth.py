"""users + audit_log tabloları — panel auth/RBAC (Faz 05)

Revision ID: 0003_auth
Revises: 0002_analyses
Create Date: 2026-10-27

İçerik:
- users tablosu (panel kimlik doğrulama özneleri; RBAC rolleri viewer/
  analyst/admin — Faz 00 kararı). Parola düz metin SAKLANMAZ: yalnızca
  argon2id hash (services/security/passwords.py).
  - UNIQUE username (küçük harfe normalize edilmiş; login aynı kuralı uygular)
  - CHECK: role enum
- audit_log tablosu (append-only denetim izi; AGENTS.md §4 "ajant kendi
  audit kayıtlarını değiştiremez"):
  - actor bilinçli olarak FK DEĞİLDİR: kullanıcı silinse bile iz kalır
  - İndeksler: created_at (zaman sıralı liste), action (filteleme)
  - Parola/token değeri ASLA yazılmaz (yazan tek kod services/security/audit;
    sabit eylem adları + yapısal detay)

Geri dönüş (downgrade): her iki tablo da bağımsızdır; events/analyses
etkilenmez. downgrade veri KAYBEDER (kullanıcılar + denetim izi) — bu
bilinçli ve belgelenmiştir: auth/RBAC kaldırıldığında panel açılmaz.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "0003_auth"
down_revision: str = "0002_analyses"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=256), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "role IN ('viewer', 'analyst', 'admin')", name="ck_users_role"
        ),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=64), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource", sa.String(length=128), nullable=False),
        sa.Column(
            "detail",
            sa.JSON().with_variant(JSONB(), "postgresql"),
            nullable=True,
        ),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
    )
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_index("ix_audit_log_created_at", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_table("users")
