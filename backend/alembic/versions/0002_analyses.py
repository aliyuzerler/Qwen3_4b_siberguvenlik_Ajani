"""analyses tablosu — model analizi kayıtları (Faz 04)

Revision ID: 0002_analyses
Revises: 0001_events
Create Date: 2026-10-27

İçerik:
- analyses tablosu (append-only model analizi; events'e FK ON DELETE CASCADE)
- UNIQUE event_id → her olay faz başına en fazla bir kez analiz edilir
  (duplicate alert yeni analiz tetiklemez; Faz 03 idempotency sözleşmesi)
- CHECK: status enum, confidence 0-1, "completed ⟺ ai_assessment dolu"
- İndeks: finished_at (panel/liste sıralaması, Faz 05)
- ai_assessment YALNIZCA bu tabloda; events.rule_level (orijinal Wazuh
  severity) asla üzerine yazılmaz (AGENTS.md §5)

Geri dönüş (downgrade): tabloyu düşürür (analyses bağımsız tablodur;
events etkilenmez — belgelenmiş geri dönüş yolu, AGENTS.md §8).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "0002_analyses"
down_revision: str = "0001_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON_VARIANT = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "analyses",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "event_id",
            sa.Uuid(),
            sa.ForeignKey("events.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("ai_assessment", sa.String(length=32), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("evidence", _JSON_VARIANT, nullable=True),
        sa.Column("alternative_explanations", _JSON_VARIANT, nullable=True),
        sa.Column("recommended_next_steps", _JSON_VARIANT, nullable=True),
        sa.Column("requires_human_review", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(length=48), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("model_tag", sa.String(length=64), nullable=False),
        sa.Column("model_quantization", sa.String(length=32), nullable=False),
        sa.Column("prompt_template_version", sa.String(length=16), nullable=False),
        sa.Column("prompt_chars", sa.Integer(), nullable=False),
        sa.Column("context_chars", sa.Integer(), nullable=False),
        sa.Column("context_truncated", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("retries_used", sa.Integer(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('completed', 'analysis_failed')", name="ck_analyses_status"
        ),
        sa.CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_analyses_confidence",
        ),
        sa.CheckConstraint(
            "(status = 'completed') = (ai_assessment IS NOT NULL)",
            name="ck_analyses_completed_has_assessment",
        ),
    )
    op.create_index("ix_analyses_finished_at", "analyses", ["finished_at"])


def downgrade() -> None:
    op.drop_index("ix_analyses_finished_at", table_name="analyses")
    op.drop_table("analyses")
