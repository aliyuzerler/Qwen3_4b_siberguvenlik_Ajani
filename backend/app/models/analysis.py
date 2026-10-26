"""analyses tablosu ORM modeli (Faz 04) — append-only model kayıtları.

Gereksinimler (phases/04, AGENTS.md §5, §6):
- "Model sürümü, süre, prompt/template sürümü ve sonuç metadata'sı kaydedilsin"
  → model_tag, model_quantization, prompt_template_version, duration_ms,
  retries_used, prompt_chars, finished_at sütunları.
- ai_assessment ayrı alanda: events.tablosundaki ORİJİNAL rule_level ASLA
  üzerine yazılmaz; model değerlendirmesi yalnızca bu tabloda yaşar
  (alert verisi ile model çıktısı asla aynı satırda karışmaz).
- status: "completed" | "analysis_failed" (güvenli fallback kaydı).
  analysis_failed satırlarında model kaynaklı alanlar (ai_assessment, summary
  vb.) NULL'dur; yalnızca error_code/error_message doludur.
- Append-only: kodda bu tabloya UPDATE/DELETE YOKTUR (ajant kendi analiz
  kayıtlarını değiştiremez — AGENTS.md §4). Satır başına UNIQUE event_id:
  her olay faz başına en fazla bir kez analiz edilir (duplicate alert yeni
  analiz tetiklemez — Faz 03 repository sözleşmesi). Yeniden analiz
  (model yükseltmesi) gelecekte ayrı migration ile açılacaktır.
- Retention: events silindiğinde analyses FK ON DELETE CASCADE ile birlikte
  silinir (analiz, olaydan bağımsız yaşamaz; süre RETENTION_DAYS).

Erişim yetkileri (belgelenmiş; compose'da uygulanan kullanıcı):
- Uygulama DB kullanıcısı: SELECT/INSERT (analyses). UPDATE/DELETE yok.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.event import FlexibleJSON, UTCDateTime

# status sütunu değerleri (CHECK kısıtıyla da korunur)
STATUS_COMPLETED = "completed"
STATUS_ANALYSIS_FAILED = "analysis_failed"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Analysis(Base):
    """Tek event'in model analizi kaydı (append-only)."""

    __tablename__ = "analyses"
    __table_args__ = (
        CheckConstraint(
            "status IN ('completed', 'analysis_failed')", name="ck_analyses_status"
        ),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_analyses_confidence",
        ),
        CheckConstraint(
            "(status = 'completed') = (ai_assessment IS NOT NULL)",
            name="ck_analyses_completed_has_assessment",
        ),
        Index("ix_analyses_finished_at", "finished_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)

    # --- İlişki: analiz olaydan bağımsız yaşamaz (retention CASCADE) ---
    event_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("events.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,  # faz başına tek analiz; yeniden analiz gelecek fazda
    )

    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(24), nullable=False)

    # --- Model kaynaklı alanlar (yalnızca completed satırlarında dolu) ---
    ai_assessment: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[list[dict[str, object]] | None] = mapped_column(
        FlexibleJSON, nullable=True
    )
    alternative_explanations: Mapped[list[str] | None] = mapped_column(
        FlexibleJSON, nullable=True
    )
    recommended_next_steps: Mapped[list[str] | None] = mapped_column(
        FlexibleJSON, nullable=True
    )
    requires_human_review: Mapped[bool | None] = mapped_column(
        # SQLite/PG uyumlu boolean saklama (integer 0/1)
        Integer,
        nullable=True,
    )

    # --- analysis_failed satırları için yapısal hata bilgisi ---
    error_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Model/prompt künyesi (her iki durumda da dolu) ---
    model_tag: Mapped[str] = mapped_column(String(64), nullable=False)
    model_quantization: Mapped[str] = mapped_column(String(32), nullable=False)
    prompt_template_version: Mapped[str] = mapped_column(String(16), nullable=False)
    prompt_chars: Mapped[int] = mapped_column(Integer, nullable=False)
    context_chars: Mapped[int] = mapped_column(Integer, nullable=False)
    context_truncated: Mapped[bool] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    retries_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finished_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=_utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover — debug kolaylığı
        return (
            f"Analysis(id={self.id!s}, event_id={self.event_id!s}, "
            f"status={self.status!r}, ai_assessment={self.ai_assessment!r})"
        )
