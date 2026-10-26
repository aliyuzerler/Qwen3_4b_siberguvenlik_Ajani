"""Analiz kayıt deposu (Faz 04) — append-only yazım + pending seçimi.

Davranış:
- save_outcome(): AnalysisOutcome'u analyses tablosuna YAZAR (completed veya
  analysis_failed). UPDATE/DELETE YOKTUR — append-only (AGENTS.md §4: ajan
  kendi analiz kayıtlarını değiştiremez).
- select_pending_events(): henüz analizi OLMAYAN event'leri (LEFT JOIN
  analyses IS NULL) en eskiden yeniye, batch limitiyle döner. UNIQUE
  event_id kısıtı sayesinde eşzamanlı yazımda ikinci yazar IntegrityError
  alır ve kayıt atlanır (yarış güvenliği; Faz 03 UNIQUE idempotency
  yaklaşımıyla aynı desen).

Hata modeli (Faz 03 deposuyla aynı disiplin):
- Retryable altyapı hatası → StorageError(retryable=True) — döngü fail-fast.
- Kalıcı tek kayıt hatası → StorageError(retryable=False) — izole edilir.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import (
    DBAPIError,
    IntegrityError,
    InterfaceError,
    OperationalError,
    SQLAlchemyError,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.analysis import (
    STATUS_ANALYSIS_FAILED,
    STATUS_COMPLETED,
    Analysis,
)
from app.models.event import Event
from app.services.analysis.analyzer import AnalysisOutcome
from app.services.analysis.errors import AnalysisError
from app.services.analysis.models import ANALYSIS_SCHEMA_VERSION
from app.services.analysis.prompt import AnalysisContext
from app.services.normalization.errors import StorageError

_RETRYABLE_EXC = (OperationalError, InterfaceError)


def _wrap_storage_error(exc: Exception) -> StorageError:
    retryable = isinstance(exc, _RETRYABLE_EXC)
    return StorageError(
        f"Veritabanı işlemi başarısız (retryable={retryable}).", retryable=retryable
    )


@dataclass(frozen=True)
class PendingEvent:
    """Analiz bekleyen tek event (ORM satırından bağlam üretimi için)."""

    event_id: str
    context: AnalysisContext


@dataclass
class SaveResult:
    """Tek outcome yazım sonucu."""

    event_id: str
    status: str  # completed | analysis_failed | skipped (yarış kaybı)


class AnalysisRepository:
    """analyses tablosuna append-only yazım + pending event seçimi."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def select_pending_events(self, *, limit: int) -> list[PendingEvent]:
        """Analizi olmayan event'leri (eskiden yeniye) bağlamla döner.

        Bağlam YALNIZCA events tablosundaki maskelenmiş/normalleştirilmiş
        alanlardan kurulur (raw_alert prompt'a ASLA girmez — phases/04).
        """
        async with self._sessionmaker() as session:
            rows = (
                await session.execute(
                    select(Event)
                    .outerjoin(Analysis, Analysis.event_id == Event.id)
                    .where(Analysis.id.is_(None))
                    .order_by(Event.timestamp.asc(), Event.id.asc())
                    .limit(limit)
                )
            ).scalars().all()
            return [_to_pending(row) for row in rows]

    async def save_outcome(self, outcome: AnalysisOutcome) -> SaveResult:
        """Tek analiz sonucunu append-only yazar.

        IntegrityError (event_id UNIQUE yarışı) → skipped döner: analiz
        zaten yapılmıştır, çoğaltma YAPILMAZ ("tekrar gelen event aynı
        analizi çoğaltmamalı" — AGENTS.md §8).
        """
        try:
            return await self._save_once(outcome)
        except IntegrityError:
            return SaveResult(event_id=outcome.event_id, status="skipped")
        except DBAPIError as exc:
            raise _wrap_storage_error(exc) from exc
        except SQLAlchemyError as exc:
            raise _wrap_storage_error(exc) from exc

    async def _save_once(self, outcome: AnalysisOutcome) -> SaveResult:
        metadata = outcome.metadata
        analysis = outcome.analysis
        completed = analysis is not None
        if analysis is not None:
            model_fields: dict[str, object] = {
                "ai_assessment": analysis.assessment.value,
                "confidence": analysis.confidence,
                "summary": analysis.summary,
                "evidence": [item.model_dump() for item in analysis.evidence],
                "alternative_explanations": list(analysis.alternative_explanations),
                "recommended_next_steps": [step.value for step in analysis.recommended_next_steps],
                "requires_human_review": 1 if analysis.requires_human_review else 0,
                "error_code": None,
                "error_message": None,
            }
        else:
            model_fields = {
                "ai_assessment": None,
                "confidence": None,
                "summary": None,
                "evidence": None,
                "alternative_explanations": None,
                "recommended_next_steps": None,
                "requires_human_review": None,
                "error_code": outcome.error_code,
                "error_message": outcome.error_message,
            }
        row = Analysis(
            event_id=uuid.UUID(outcome.event_id),  # Uuid() tipi UUID nesnesi bekler
            schema_version=ANALYSIS_SCHEMA_VERSION,
            status=STATUS_COMPLETED if completed else STATUS_ANALYSIS_FAILED,
            model_tag=metadata.model_tag,
            model_quantization=metadata.model_quantization,
            prompt_template_version=metadata.prompt_template_version,
            prompt_chars=metadata.prompt_chars,
            context_chars=metadata.context_chars,
            context_truncated=1 if metadata.context_truncated else 0,
            duration_ms=metadata.duration_ms,
            retries_used=metadata.retries_used,
            finished_at=metadata.finished_at,
            **model_fields,  # type: ignore[arg-type]
        )
        async with self._sessionmaker() as session, session.begin():
            session.add(row)
        return SaveResult(event_id=outcome.event_id, status=row.status)


def _to_pending(row: Event) -> PendingEvent:
    """Event ORM satırını analiz bağlamına çevirir (yalnızca maskeli alanlar)."""
    if row.id is None:  # pragma: no cover — PK her zaman dolu
        raise AnalysisError("Event satırında id beklenmedik biçimde boş.")
    context = AnalysisContext(
        event_id=str(row.id),
        alert_id=row.alert_id,
        timestamp=_ensure_utc(row.timestamp),
        rule_id=row.rule_id,
        rule_level=row.rule_level,  # ORİJİNAL severity — bağlamda okunur, değişmez
        rule_description=row.rule_description,
        rule_groups=list(row.rule_groups or []),
        agent_id=row.agent_id,
        agent_name=row.agent_name,
        manager=row.manager,
        location=row.location,
        decoder=row.decoder,
        src_ip=row.src_ip,
        full_log_redacted=row.full_log_redacted,
    )
    return PendingEvent(event_id=str(row.id), context=context)


def _ensure_utc(value: datetime) -> datetime:
    """Okuma tarafında tz garantisi (UTCDateTime TypeDecorator ile aynı kural)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


__all__ = ["AnalysisRepository", "PendingEvent", "SaveResult"]
