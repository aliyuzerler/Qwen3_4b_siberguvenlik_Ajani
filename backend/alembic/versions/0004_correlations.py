"""correlation_rules + correlations + correlation_events — korelasyon (Faz 06)

Revision ID: 0004_correlations
Revises: 0003_auth
Create Date: 2026-10-27

İçerik:
- correlation_rules: kural kataloğunun DB yansıması (key PK, version >= 1,
  kind enum CHECK, params JSONB, enabled operatör anahtarı). Katalog KOD
  kaynaklıdır; startup senkronu upsert yapar ve sürüm değişimini audit'ler.
- correlations: kural tespitleri (append-baskın; UPDATE yalnızca
  hit_count/last_hit_at — events.seen_count kalıbı; DELETE kod yolu yok).
  - rule_key FK (NO ACTION): kural satırı silinirken tespit varsa engellenir
    (kural silme kod yolu yok; bütünlük DB seviyesinde de korunur).
  - dedup_key UNIQUE: aynı kural+grup+pencere yeniden tespit edilirse yeni
    satır yazılmaz, hit_count artar (duplicate/near-duplicate yönetimi).
  - max_rule_level: ORİJİNAL Wazuh severity'si (LLM asla yazmaz; kural
    çıktısı ile model yorumu ayrı tablolarda — AGENTS.md §5/§8).
- correlation_events: kanıt bağlantıları; iki FK de ON DELETE CASCADE
  (event retention'da silinince bağlantılar da temizlenir).

Geri dönüş (downgrade): üç tablo bağımsızdır, sırayla düşürülür; events/
analyses/users etkilenmez. Downgrade tespit kayıtlarını KAYBEDER (bilinçli,
belgelenmiş geri dönüş yolu — AGENTS.md §8).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "0004_correlations"
down_revision: str = "0003_auth"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON_VARIANT = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "correlation_rules",
        sa.Column("key", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=512), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("params", _JSON_VARIANT, nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("version >= 1", name="ck_correlation_rules_version"),
        sa.CheckConstraint(
            "kind IN ('burst', 'sequence')", name="ck_correlation_rules_kind"
        ),
    )

    op.create_table(
        "correlations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "rule_key",
            sa.String(length=64),
            sa.ForeignKey("correlation_rules.key"),
            nullable=False,
        ),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("dedup_key", sa.String(length=64), nullable=False, unique=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("max_rule_level", sa.Integer(), nullable=False),
        sa.Column("evidence", _JSON_VARIANT, nullable=False),
        sa.Column("hit_count", sa.Integer(), nullable=False),
        sa.Column("first_hit_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_hit_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "rule_version >= 1", name="ck_correlations_rule_version"
        ),
        sa.CheckConstraint("event_count >= 1", name="ck_correlations_event_count"),
        sa.CheckConstraint("hit_count >= 1", name="ck_correlations_hit_count"),
        sa.CheckConstraint(
            "max_rule_level >= 0 AND max_rule_level <= 15",
            name="ck_correlations_max_rule_level",
        ),
    )
    op.create_index("ix_correlations_window_start", "correlations", ["window_start"])
    op.create_index("ix_correlations_rule_key", "correlations", ["rule_key"])

    op.create_table(
        "correlation_events",
        sa.Column(
            "correlation_id",
            sa.Uuid(),
            sa.ForeignKey("correlations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "event_id",
            sa.Uuid(),
            sa.ForeignKey("events.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_correlation_events_event_id", "correlation_events", ["event_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_correlation_events_event_id", table_name="correlation_events")
    op.drop_table("correlation_events")
    op.drop_index("ix_correlations_rule_key", table_name="correlations")
    op.drop_index("ix_correlations_window_start", table_name="correlations")
    op.drop_table("correlations")
    op.drop_table("correlation_rules")
