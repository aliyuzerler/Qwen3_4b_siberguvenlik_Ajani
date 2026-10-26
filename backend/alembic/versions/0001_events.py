"""events tablosu — ilk migration (Faz 03)

Revision ID: 0001_events
Revises: -
Create Date: 2026-10-27

İçerik:
- events tablosu (sürümlenmiş event modeli, v1)
- UNIQUE idempotency_key (tekrar gelen alert yeni satır üretmez)
- İndeksler: timestamp (zaman penceresi sorguları + retention purge),
  (source, alert_id) (adapter'dan gelen kimlik araması), fingerprint (değişik
  payload teşhisi)
- CHECK rule_level 0-15 (orijinal Wazuh severity aralığı; kanonik int)

Geri dönüş (downgrade): tabloyu düşürür. Faz 04'te analyses tablosu bu
tabloya FK ile bağlanacaktır; o fazdan sonra downgrade sırası önce
analyses'i düşürür (belgelenmiş geri dönüş yolu — AGENTS.md §8).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "0001_events"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# JSONB PostgreSQL'de; diğer dialektlerde (sqlite) standart JSON'a döner.
_JSON_VARIANT = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False, unique=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("rule_level", sa.Integer(), nullable=False),
        sa.Column("rule_description", sa.String(length=512), nullable=False),
        sa.Column("rule_groups", _JSON_VARIANT, nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=True),
        sa.Column("agent_name", sa.String(length=255), nullable=True),
        sa.Column("manager", sa.String(length=255), nullable=True),
        sa.Column("location", sa.String(length=255), nullable=True),
        sa.Column("decoder", sa.String(length=255), nullable=True),
        sa.Column("full_log_redacted", sa.Text(), nullable=True),
        sa.Column("src_ip", sa.String(length=64), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("seen_count", sa.Integer(), nullable=False),
        sa.Column("variant_count", sa.Integer(), nullable=False),
        sa.Column("raw_alert", _JSON_VARIANT, nullable=True),
        sa.CheckConstraint("rule_level >= 0 AND rule_level <= 15", name="ck_events_rule_level"),
    )
    op.create_index("ix_events_timestamp", "events", ["timestamp"])
    op.create_index("ix_events_source_alert_id", "events", ["source", "alert_id"])
    op.create_index("ix_events_fingerprint", "events", ["fingerprint"])


def downgrade() -> None:
    op.drop_index("ix_events_fingerprint", table_name="events")
    op.drop_index("ix_events_source_alert_id", table_name="events")
    op.drop_index("ix_events_timestamp", table_name="events")
    op.drop_table("events")
