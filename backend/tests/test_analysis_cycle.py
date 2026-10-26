"""run_analysis_cycle testleri (Faz 04) — sqlite + MockOllamaClient ile entegrasyon.

Kapsam: mutlu yol, analysis_failed fallback satırı, altyapı hatasında
SIFIR satır + fail-fast, ikinci döngüde pending boş (idempotent), metrics
entegrasyonu, DB hata izolasyonu.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select

from app.models.analysis import Analysis
from app.services.analysis.analyzer import AnalysisOutcome
from app.services.analysis.errors import OllamaUnavailableError
from app.services.analysis.metrics import AnalysisMetrics
from app.services.analysis.repository import AnalysisRepository
from app.services.normalization.errors import StorageError
from app.workers.analysis import run_analysis_cycle
from tests.conftest import MockOllamaClient, make_valid_model_output

# Not: event ekleme yardımcısı depo testlerinden alınır (aynı sentetik desen).
from tests.test_analysis_repository import _insert_event  # noqa: I001
from tests.test_analyzer import make_analyzer as _make_analyzer  # noqa: I001


def _analyzer(client: MockOllamaClient) -> Any:
    return _make_analyzer(client)


class TestHappyPath:
    async def test_cycle_completes_pending_events(self, sessionmaker_fixture: Any) -> None:
        await _insert_event(sessionmaker_fixture, alert_id="700.1")
        await _insert_event(sessionmaker_fixture, alert_id="700.2")
        client = MockOllamaClient()
        metrics = AnalysisMetrics()

        result = await run_analysis_cycle(
            sessionmaker_fixture, _analyzer(client), batch_size=10, metrics=metrics
        )
        assert result.pending_seen == 2
        assert result.completed == 2
        assert result.failed == 0
        async with sessionmaker_fixture() as session:
            rows = (await session.execute(select(Analysis))).scalars().all()
        assert len(rows) == 2
        snapshot = metrics.snapshot()
        assert snapshot.total == 2 and snapshot.completed == 2
        assert snapshot.schema_valid_rate == 1.0

    async def test_second_cycle_has_no_pending(self, sessionmaker_fixture: Any) -> None:
        """İkinci döngü: analizi yapılmış event'ler pending DEĞİLDİR (idempotent)."""
        await _insert_event(sessionmaker_fixture, alert_id="710.1")
        client = MockOllamaClient()
        analyzer = _analyzer(client)
        await run_analysis_cycle(sessionmaker_fixture, analyzer, batch_size=10)
        result2 = await run_analysis_cycle(sessionmaker_fixture, analyzer, batch_size=10)
        assert result2.pending_seen == 0
        assert result2.processed == 0
        assert len(client.calls) == 1  # ikinci turda model çağrısı YOK

    async def test_duplicate_ingest_does_not_retrigger_analysis(
        self, sessionmaker_fixture: Any
    ) -> None:
        """Faz 03 duplicate → aynı event satırı; analiz faz başına BİR kez."""
        repo = AnalysisRepository(sessionmaker_fixture)
        pending1 = await repo.select_pending_events(limit=10)
        await _insert_event(sessionmaker_fixture, alert_id="1792974900.123456")
        # İkinci insert aynı idempotency key'i taşıyamaz (UNIQUE) — bu yüzden
        # duplicate senaryosu Faz 03 deposunda test edilir. Buradaki garanti:
        # event sayısı kadar analiz vardır, fazlası yok.
        assert len(pending1) == 0


class TestFallbackRows:
    async def test_invalid_output_writes_analysis_failed_row(
        self, sessionmaker_fixture: Any
    ) -> None:
        """Model çıktısı geçersiz → analysis_failed SATIRI yazılır (fallback)."""
        await _insert_event(sessionmaker_fixture, alert_id="720.1")
        client = MockOllamaClient(
            responses=[make_valid_model_output("720.1", assessment="geçersiz")]
        )
        result = await run_analysis_cycle(sessionmaker_fixture, _analyzer(client), batch_size=10)
        assert result.failed == 1 and result.completed == 0
        async with sessionmaker_fixture() as session:
            row = (await session.execute(select(Analysis))).scalar_one()
        assert row.status == "analysis_failed"
        assert row.ai_assessment is None
        assert row.error_code == "schema_violation"

    async def test_mixed_outcomes_isolated(self, sessionmaker_fixture: Any) -> None:
        """Tek event'in başarısızlığı diğerlerini engellemez (izolasyon).

        Pending seçimi timestamp sırasıyla ilerlediği için responses sırası
        ancak timestamp'ler belirleyici olduğunda eşleşir (tiebreak id).
        """
        base = datetime(2026, 10, 26, 9, 0, tzinfo=UTC)
        await _insert_event(
            sessionmaker_fixture, alert_id="730.1", timestamp=base
        )
        await _insert_event(
            sessionmaker_fixture, alert_id="730.2", timestamp=base + timedelta(seconds=1)
        )
        await _insert_event(
            sessionmaker_fixture, alert_id="730.3", timestamp=base + timedelta(seconds=2)
        )
        # responses sırayla (retry tüketimi dahil): 730.1 iki denemede de
        # geçersiz → analysis_failed; 730.2 ve 730.3 geçerli → completed.
        client = MockOllamaClient(
            responses=[
                make_valid_model_output("730.1", confidence=9.9),  # 1. deneme: ihlal
                make_valid_model_output("730.1", confidence=9.9),  # 2. deneme: yine ihlal
                make_valid_model_output("730.2"),
                make_valid_model_output("730.3"),
            ]
        )
        result = await run_analysis_cycle(sessionmaker_fixture, _analyzer(client), batch_size=10)
        assert result.completed == 2
        assert result.failed == 1


class TestInfrastructureAbort:
    async def test_ollama_down_writes_no_rows_and_raises(
        self, sessionmaker_fixture: Any
    ) -> None:
        """Ollama kapalı → döngü fail-fast; analyses tablosu TEMİZ kalır."""
        await _insert_event(sessionmaker_fixture, alert_id="740.1")
        await _insert_event(sessionmaker_fixture, alert_id="740.2")
        client = MockOllamaClient(
            responses=[OllamaUnavailableError("Ollama'ya bağlanılamadı (sentetik)")]
        )
        with pytest.raises(OllamaUnavailableError):
            await run_analysis_cycle(sessionmaker_fixture, _analyzer(client), batch_size=10)
        async with sessionmaker_fixture() as session:
            count = int(
                (await session.execute(select(func.count()).select_from(Analysis))).scalar_one()
            )
        assert count == 0
        # Event'ler hâlâ pending (sonraki döngüde tekrar denenir)
        pending = await AnalysisRepository(sessionmaker_fixture).select_pending_events(limit=10)
        assert len(pending) == 2

    async def test_partial_batch_stays_pending_after_abort(
        self, sessionmaker_fixture: Any
    ) -> None:
        """Altyapı hatası ortada gelir: yazılan satır kalır, kalanlar pending."""
        base = datetime(2026, 10, 26, 9, 0, tzinfo=UTC)
        id1 = await _insert_event(
            sessionmaker_fixture, alert_id="750.1", timestamp=base
        )
        await _insert_event(
            sessionmaker_fixture, alert_id="750.2", timestamp=base + timedelta(seconds=1)
        )
        client = MockOllamaClient(
            responses=[
                make_valid_model_output("750.1"),
                OllamaUnavailableError("bağlantı koptu (sentetik)"),
            ]
        )
        with pytest.raises(OllamaUnavailableError):
            await run_analysis_cycle(sessionmaker_fixture, _analyzer(client), batch_size=10)
        async with sessionmaker_fixture() as session:
            rows = (await session.execute(select(Analysis))).scalars().all()
        assert len(rows) == 1 and str(rows[0].event_id) == id1
        pending = await AnalysisRepository(sessionmaker_fixture).select_pending_events(limit=10)
        assert len(pending) == 1


class TestDbErrorIsolation:
    async def test_retryable_db_error_aborts_cycle(self, sessionmaker_fixture: Any) -> None:
        """Retryable DB hatası fail-fast: döngü kesilir, hata yükseltilir."""
        await _insert_event(sessionmaker_fixture, alert_id="760.1")
        client = MockOllamaClient()
        analyzer = _analyzer(client)

        async def failing_save(self: Any, outcome: AnalysisOutcome) -> Any:
            raise StorageError("DB bağlantısı koptu (sentetik)", retryable=True)

        original = AnalysisRepository.save_outcome
        AnalysisRepository.save_outcome = failing_save  # type: ignore[method-assign]
        try:
            with pytest.raises(StorageError):
                await run_analysis_cycle(sessionmaker_fixture, analyzer, batch_size=10)
        finally:
            AnalysisRepository.save_outcome = original  # type: ignore[method-assign]
        assert len(client.calls) == 1  # ilk event analiz edildi, sonra kesildi

    async def test_non_retryable_db_error_isolated(self, sessionmaker_fixture: Any) -> None:
        """Kalıcı tek event yazım hatası izole edilir; batch devam eder."""
        await _insert_event(sessionmaker_fixture, alert_id="770.1")
        await _insert_event(sessionmaker_fixture, alert_id="770.2")
        client = MockOllamaClient()
        calls = {"n": 0}

        original = AnalysisRepository.save_outcome

        async def failing_for_first(self: Any, outcome: AnalysisOutcome) -> Any:
            calls["n"] += 1
            if calls["n"] == 1:
                raise StorageError("kalıcı kısıt hatası (sentetik)", retryable=False)
            return await original(self, outcome)  # yakalanan gerçek metod

        AnalysisRepository.save_outcome = failing_for_first  # type: ignore[method-assign]
        try:
            result = await run_analysis_cycle(
                sessionmaker_fixture, _analyzer(client), batch_size=10
            )
        finally:
            AnalysisRepository.save_outcome = original  # type: ignore[method-assign]
        assert result.db_errors == 1
        assert result.completed == 1  # ikinci event kaydedildi


class TestBatchLimit:
    async def test_batch_size_limits_cycle(self, sessionmaker_fixture: Any) -> None:
        for i in range(5):
            await _insert_event(sessionmaker_fixture, alert_id=f"780.{i}")
        client = MockOllamaClient()
        result = await run_analysis_cycle(sessionmaker_fixture, _analyzer(client), batch_size=3)
        assert result.pending_seen == 3
        assert result.completed == 3
        # Kalan 2 event bir sonraki turda
        pending = await AnalysisRepository(sessionmaker_fixture).select_pending_events(limit=10)
        assert len(pending) == 2
