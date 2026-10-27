"""remediation_actions — güvenli müdahale hazırlığı (Faz 07)

Revision ID: 0005_remediation
Revises: 0004_correlations
Create Date: 2026-10-27

İçerik:
- remediation_catalog: katalog operatör anahtarı (action_type PK, enabled).
  Tanım KOD kaynaklıdır; DB yalnızca operatör enabled kararını taşır
  (correlation_rules kalıbı; startup senkronu idempotent upsert).
  Varsayılan: normal aksiyonlar enabled=true; default_blocked (firewall/
  SSH/hesap) enabled=false.
- remediation_actions: müdahale önerileri + yaşam döngüsü (append-baskın).
  - status CHECK enum: proposed/approved/rejected/expired/executed/failed.
    Satır SİLİNMEZ; durum geçişleri audit_log ile birlikte yaşar (AGENTS.md
    §4: ajan kendi kayıtlarını silemez/değiştiremez — UPDATE yalnızca durum
    geçiş alanlarındadır).
  - idempotency_key UNIQUE: öneri oluşturma tekrarı (istemci retry) yeni
    satır üretmez.
  - execution_key UNIQUE: yürütme tekrar koruması — aynı anahtarla gelen
    ikinci istek orijinal sonucu döner (replayed=true), çift yürütme OLMAZ.
  - action_type CHECK enum: allowlist dışı tip DB seviyesinde de reddedilir
    (politika motoruna ek savunma derinliği).
  - risk_level CHECK: low/medium/high (katalog snapshot).
  - requested_by_user_id / approved_by_user_id FK → users.id ON DELETE
    SET NULL: kullanıcı silinse de iz kaydı (username snapshot) kalır.
  - evidence / policy_decision / params / execution_result: JSONB
    (PostgreSQL JSONB; sqlite JSON varyantı).

Geri dönüş (downgrade): iki tablo bağımsız düşürülür; events/analyses/
users/correlations etkilenmez. Downgrade öneri/onay/yürütme izlerini
KAYBEDER (bilinçli, belgelenmiş geri dönüş yolu — AGENTS.md §8).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "0005_remediation"
down_revision: str = "0004_correlations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON_VARIANT = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "remediation_catalog",
        sa.Column("action_type", sa.String(length=32), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "remediation_actions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False, unique=True),
        sa.Column("action_type", sa.String(length=32), nullable=False),
        sa.Column("action_title", sa.String(length=128), nullable=False),
        sa.Column("risk_level", sa.String(length=8), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "requested_by_user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("requested_by_username", sa.String(length=64), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("params", _JSON_VARIANT, nullable=False),
        sa.Column("evidence", _JSON_VARIANT, nullable=False),
        sa.Column("policy_decision", _JSON_VARIANT, nullable=False),
        sa.Column(
            "approved_by_user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("approved_by_username", sa.String(length=64), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejected_by_username", sa.String(length=64), nullable=True),
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejected_reason", sa.String(length=500), nullable=True),
        sa.Column("execution_key", sa.String(length=64), nullable=True, unique=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_count", sa.Integer(), nullable=False),
        sa.Column("execution_result", _JSON_VARIANT, nullable=True),
        sa.Column("execution_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('proposed', 'approved', 'rejected', 'expired', "
            "'executed', 'failed')",
            name="ck_remediation_actions_status",
        ),
        sa.CheckConstraint(
            "action_type IN ('notify_admin', 'restart_wazuh_agent', "
            "'run_antivirus_scan', 'block_src_ip', 'isolate_host', "
            "'lock_user_account')",
            name="ck_remediation_actions_action_type",
        ),
        sa.CheckConstraint(
            "risk_level IN ('low', 'medium', 'high')",
            name="ck_remediation_actions_risk_level",
        ),
        sa.CheckConstraint(
            "execution_count >= 0", name="ck_remediation_actions_execution_count"
        ),
    )
    op.create_index(
        "ix_remediation_actions_status", "remediation_actions", ["status"]
    )
    op.create_index(
        "ix_remediation_actions_created_at", "remediation_actions", ["created_at"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_remediation_actions_created_at", table_name="remediation_actions"
    )
    op.drop_index("ix_remediation_actions_status", table_name="remediation_actions")
    op.drop_table("remediation_actions")
    op.drop_table("remediation_catalog")
