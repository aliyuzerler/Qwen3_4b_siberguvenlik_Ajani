"""AnalysisRepository testleri (Faz 04) — append-only yazım + pending seçim.

Kapsam: completed/failed kayıt, pending seçim (LEFT JOIN, eski→yeni, limit),
UNIQUE event_id yarışı (skipped), FK CASCADE retention davranışı, events
satırının analizden etkilenmemesi (severity dokunulmazlığı).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.analysis import Analysis
from app.models.event import Event
from app.services.analysis.analyzer import AnalysisMetadata, AnalysisOutcome
from app.services.analysis.models import parse_model_analysis
from app.services.analysis.repository import AnalysisRepository
from tests.conftest import make_valid_model_output


def _metadata(**overrides: Any) -> AnalysisMetadata:
    values: dict[str, Any] = {
        "model_tag": "qwen3:4b",
        "model_quantization": "Q4_K_M",
        "prompt_template_version": "v1",
        "prompt_chars": 1234,
        "context_chars": 500,
        "context_truncated": False,
        "duration_ms": 321,
        "retries_used": 0,
        "finished_at": datetime(2026, 10, 26, 9, 20, 0, tzinfo=UTC),
    }
    values.update(overrides)
    return AnalysisMetadata(**values)


def _completed_outcome(event_id: str) -> AnalysisOutcome:
    analysis = parse_model_analysis(make_valid_model_output(), max_chars=6000)
    return AnalysisOutcome.completed(event_id, analysis, _metadata())


def _failed_outcome(event_id: str) -> AnalysisOutcome:
    return AnalysisOutcome.failed(
        event_id, "schema_violation", "model çıktısı şemayı ihlal etti", _metadata(duration_ms=77)
    )


async def _insert_event(
    maker: async_sessionmaker[AsyncSession],
    *,
    event_id: Any = None,
    alert_id: str = "1792974900.123456",
    timestamp: datetime | None = None,
) -> str:
    """Test event satırı ekler; str UUID döner."""
    row = Event(
        schema_version=1,
        source="wazuh",
        alert_id=alert_id,
        idempotency_key=f"key-{alert_id}",
        timestamp=timestamp or datetime(2026, 10, 26, 9, 15, 0, tzinfo=UTC),
        received_at=datetime.now(UTC),
        rule_id="5712",
        rule_level=10,
        rule_description="sshd: Brute force.",
        rule_groups=["syslog"],
        fingerprint=f"fp-{alert_id}",
        seen_count=1,
        variant_count=0,
    )
    if event_id is not None:
        row.id = event_id
    async with maker() as session, session.begin():
        session.add(row)
        await session.flush()
        return str(row.id)


class TestSaveOutcome:
    async def test_save_completed_row(self, sessionmaker_fixture: Any) -> None:
        repo = AnalysisRepository(sessionmaker_fixture)
        event_id = await _insert_event(sessionmaker_fixture)
        result = await repo.save_outcome(_completed_outcome(event_id))
        assert result.status == "completed"
        async with sessionmaker_fixture() as session:
            row = (await session.execute(select(Analysis))).scalar_one()
        assert str(row.event_id) == event_id
        assert row.status == "completed"
        assert row.ai_assessment == "suspicious"
        assert row.confidence == 0.7
        assert row.summary is not None and row.summary.endswith("gözlemlendi.")
        assert row.evidence is not None and len(row.evidence) == 2
        assert row.recommended_next_steps == ["review_full_logs", "correlate_related_events"]
        assert row.requires_human_review == 1  # sqlite integer
        assert row.error_code is None and row.error_message is None
        # Model künyesi metadata'dan
        assert row.model_tag == "qwen3:4b"
        assert row.model_quantization == "Q4_K_M"
        assert row.prompt_template_version == "v1"
        assert row.duration_ms == 321 and row.retries_used == 0
        assert row.finished_at == datetime(2026, 10, 26, 9, 20, 0, tzinfo=UTC)

    async def test_save_failed_row_has_null_model_fields(
        self, sessionmaker_fixture: Any
    ) -> None:
        """analysis_failed satırında model kaynaklı alanlar NULL; hata kodu dolu."""
        repo = AnalysisRepository(sessionmaker_fixture)
        event_id = await _insert_event(sessionmaker_fixture, alert_id="1792974900.2")
        result = await repo.save_outcome(_failed_outcome(event_id))
        assert result.status == "analysis_failed"
        async with sessionmaker_fixture() as session:
            row = (await session.execute(select(Analysis))).scalar_one()
        assert row.status == "analysis_failed"
        assert row.ai_assessment is None
        assert row.confidence is None and row.summary is None
        assert row.error_code == "schema_violation"
        assert row.error_message is not None
        assert row.duration_ms == 77

    async def test_duplicate_event_id_yields_skipped_race(
        self, sessionmaker_fixture: Any
    ) -> None:
        """UNIQUE event_id yarışı: ikinci yazım skipped döner; çoğaltma YOK."""
        repo = AnalysisRepository(sessionmaker_fixture)
        event_id = await _insert_event(sessionmaker_fixture, alert_id="1792974900.3")
        first = await repo.save_outcome(_completed_outcome(event_id))
        assert first.status == "completed"
        second = await repo.save_outcome(_completed_outcome(event_id))
        assert second.status == "skipped"
        async with sessionmaker_fixture() as session:
            count = int(
                (
                    await session.execute(select(func.count()).select_from(Analysis))
                ).scalar_one()
            )
        assert count == 1


class TestPendingSelection:
    async def test_pending_excludes_analyzed_and_orders_oldest_first(
        self, sessionmaker_fixture: Any
    ) -> None:
        repo = AnalysisRepository(sessionmaker_fixture)
        old_id = await _insert_event(
            sessionmaker_fixture,
            alert_id="100.1",
            timestamp=datetime(2026, 10, 26, 8, 0, tzinfo=UTC),
        )
        mid_id = await _insert_event(
            sessionmaker_fixture,
            alert_id="100.2",
            timestamp=datetime(2026, 10, 26, 9, 0, tzinfo=UTC),
        )
        new_id = await _insert_event(
            sessionmaker_fixture,
            alert_id="100.3",
            timestamp=datetime(2026, 10, 26, 10, 0, tzinfo=UTC),
        )
        await repo.save_outcome(_completed_outcome(mid_id))  # ortadaki analizli

        pending = await repo.select_pending_events(limit=10)
        assert [p.event_id for p in pending] == [old_id, new_id]  # eski → yeni

    async def test_pending_limit_respected(self, sessionmaker_fixture: Any) -> None:
        repo = AnalysisRepository(sessionmaker_fixture)
        for i in range(5):
            await _insert_event(
                sessionmaker_fixture, alert_id=f"200.{i}"
            )
        pending = await repo.select_pending_events(limit=3)
        assert len(pending) == 3

    async def test_pending_context_carries_masked_fields_only(
        self, sessionmaker_fixture: Any
    ) -> None:
        """Bağlam yalnızca events kolonlarından kurulur; raw_alert prompt'a girmez."""

        repo = AnalysisRepository(sessionmaker_fixture)
        raw_copy = {"password": "SAHTE_SIFRE", "id": "300.1"}
        async with sessionmaker_fixture() as session, session.begin():
            row = Event(
                schema_version=1,
                source="wazuh",
                alert_id="300.1",
                idempotency_key="key-300.1",
                timestamp=datetime(2026, 10, 26, 9, 15, tzinfo=UTC),
                received_at=datetime.now(UTC),
                rule_id="5712",
                rule_level=10,
                rule_description="sshd: Brute force.",
                rule_groups=[],
                full_log_redacted="maskeli log",
                src_ip="203.0.113.7",
                fingerprint="fp-300.1",
                seen_count=1,
                variant_count=0,
                raw_alert=raw_copy,  # STORE_RAW_ALERT=true senaryosu
            )
            session.add(row)
            await session.flush()

        pending = await repo.select_pending_events(limit=10)
        assert len(pending) == 1
        context = pending[0].context
        assert context.full_log_redacted == "maskeli log"
        assert context.alert_id == "300.1"
        assert context.rule_level == 10
        # Ham alert (password'lu) bağlamda YOK
        assert not any(
            "SAHTE_SIFRE" in str(getattr(context, field))
            for field in context.__dataclass_fields__
        )

    async def test_empty_db_no_pending(self, sessionmaker_fixture: Any) -> None:
        pending = await AnalysisRepository(sessionmaker_fixture).select_pending_events(limit=10)
        assert pending == []


class TestCascadeRetention:
    async def test_event_delete_cascades_analysis(self, sessionmaker_fixture: Any) -> None:
        """Retention: event silinince analiz de silinir (FK ON DELETE CASCADE)."""
        repo = AnalysisRepository(sessionmaker_fixture)
        event_id = await _insert_event(sessionmaker_fixture, alert_id="400.1")
        await repo.save_outcome(_completed_outcome(event_id))
        async with sessionmaker_fixture() as session, session.begin():
            await session.execute(delete(Event).where(Event.id == uuid.UUID(event_id)))
        async with sessionmaker_fixture() as session:
            count = int(
                (await session.execute(select(func.count()).select_from(Analysis))).scalar_one()
            )
        assert count == 0


class TestAppendOnly:
    async def test_repository_has_no_update_or_delete_api(self) -> None:
        """Append-only sözleşme: API yüzeyinde UPDATE/DELETE yok."""
        public_methods = {
            name for name in AnalysisRepository.__dict__ if not name.startswith("_")
        }
        assert public_methods == {"select_pending_events", "save_outcome"}

    async def test_analysis_failure_does_not_touch_event_severity(
        self, sessionmaker_fixture: Any
    ) -> None:
        """Analiz kaydı events satırını DEĞİŞTİRMEZ (orijinal severity korunur)."""
        repo = AnalysisRepository(sessionmaker_fixture)
        event_id = await _insert_event(sessionmaker_fixture, alert_id="500.1")
        before = await self._read_event(sessionmaker_fixture, event_id)
        await repo.save_outcome(_completed_outcome(event_id))
        after = await self._read_event(sessionmaker_fixture, event_id)
        assert before == after

    async def _read_event(self, maker: Any, event_id: str) -> tuple[Any, ...]:
        async with maker() as session:
            row = await session.get(Event, uuid.UUID(event_id))
            return (row.rule_level, row.rule_description, row.seen_count, row.fingerprint)


class TestDbConstraints:
    async def test_confidence_check_constraint_rejects_out_of_range(
        self, sessionmaker_fixture: Any
    ) -> None:
        """DB düzeyinde de savunma: confidence 0-1 dışı CHECK ihlali."""
        from sqlalchemy.exc import IntegrityError

        event_id = await _insert_event(sessionmaker_fixture, alert_id="600.1")
        async with sessionmaker_fixture() as session, session.begin():
            session.add(
                Analysis(
                    event_id=uuid.UUID(event_id),
                    schema_version=1,
                    status="completed",
                    ai_assessment="suspicious",
                    confidence=1.5,  # kısıt ihlali
                    model_tag="t",
                    model_quantization="Q",
                    prompt_template_version="v1",
                    prompt_chars=1,
                    context_chars=1,
                    context_truncated=0,
                    duration_ms=1,
                    retries_used=0,
                    finished_at=datetime.now(UTC),
                )
            )
            with pytest.raises(IntegrityError):
                await session.flush()

    async def test_invalid_status_rejected_by_check(
        self, sessionmaker_fixture: Any
    ) -> None:
        from sqlalchemy.exc import IntegrityError

        event_id = await _insert_event(sessionmaker_fixture, alert_id="600.2")
        async with sessionmaker_fixture() as session, session.begin():
            session.add(
                Analysis(
                    event_id=uuid.UUID(event_id),
                    schema_version=1,
                    status="pending",  # kısıt ihlali
                    model_tag="t",
                    model_quantization="Q",
                    prompt_template_version="v1",
                    prompt_chars=1,
                    context_chars=1,
                    context_truncated=0,
                    duration_ms=1,
                    retries_used=0,
                    finished_at=datetime.now(UTC),
                )
            )
            with pytest.raises(IntegrityError):
                await session.flush()
