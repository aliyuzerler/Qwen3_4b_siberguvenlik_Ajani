"""Birleşik worker döngüsü testleri (Faz 04): fetch → store → analyze.

Kapsam: tek turda ingest+analiz, cursor ilerlemesi + duplicate analiz yok,
altyapı hatasında döngünün ÇÖKMEDİĞİ, stop_event ile temiz çıkış,
varsayılan kapalılık (WORKER_LOOP_ENABLED=false → task yok).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

import app.models  # noqa: F401  # Event/Analysis'i Base.metadata'ya kaydeder
from app.core.db import Base, register_sqlite_fk_pragma
from app.main import create_app, lifespan
from app.models.analysis import Analysis
from app.models.event import Event
from app.services.analysis.metrics import AnalysisMetrics
from app.services.normalization.redaction import RedactionPolicy
from app.services.wazuh.mock_source import MockWazuhAlertSource
from app.services.wazuh.models import AlertPage
from app.workers.loop import WorkerLoopStats, run_worker_loop
from tests.conftest import MockOllamaClient, make_alert, make_settings
from tests.test_analyzer import make_analyzer

POLICY = RedactionPolicy()


class _FixedSource(MockWazuhAlertSource):
    """Tek sayfa döndüren sabit kaynak (since filtresi uygulanır)."""

    def __init__(self, alerts: list[Any]) -> None:
        super().__init__()
        self._alerts = alerts

    async def list_alerts(self, query: Any) -> AlertPage:
        items = [
            alert for alert in self._alerts if query.since is None or alert.timestamp >= query.since
        ]
        return AlertPage(items=items, total=len(items), offset=query.offset, limit=query.limit)


async def _make_db(tmp_path: Any, name: str) -> tuple[AsyncEngine, async_sessionmaker[Any]]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/{name}.db")
    register_sqlite_fk_pragma(engine)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def _count(maker: Any, model: Any) -> int:
    async with maker() as session:
        return int(
            (await session.execute(select(func.count()).select_from(model))).scalar_one()
        )


async def _wait_until(predicate: Any, *, timeout: float = 3.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if await predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("koşul zaman aşımında sağlanamadı")


def _at_least(maker: Any, model: Any, minimum: int) -> Any:
    async def check() -> bool:
        return await _count(maker, model) >= minimum

    return check


class TestSingleTurn:
    async def test_one_turn_ingests_and_analyzes(self, tmp_path: Any) -> None:
        """Tek tur: 2 alert → 2 event → 2 analiz satırı; stop ile temiz çıkış."""
        engine, maker = await _make_db(tmp_path, "loop1")
        # Cursor penceresi 'şimdi'ye göre hesaplanır → alert'ler güncel olmalı
        recent = datetime.now(UTC)
        source = _FixedSource(
            [
                make_alert(alert_id="900.1", timestamp=recent - timedelta(seconds=120)),
                make_alert(alert_id="900.2", timestamp=recent - timedelta(seconds=60)),
            ]
        )
        client = MockOllamaClient()
        analyzer = make_analyzer(client)
        metrics = AnalysisMetrics()
        stop = asyncio.Event()
        stats = WorkerLoopStats()

        loop_task = asyncio.create_task(
            run_worker_loop(
                maker,
                analyzer,
                stop_event=stop,
                interval_seconds=5.0,
                batch_size=10,
                metrics=metrics,
                source=source,
                policy=POLICY,
                initial_window_seconds=3600,
                stats=stats,
            )
        )

        await _wait_until(_at_least(maker, Analysis, 2))
        stop.set()
        await asyncio.wait_for(loop_task, timeout=3.0)

        assert await _count(maker, Event) == 2
        assert await _count(maker, Analysis) == 2
        assert stats.ingest_cycles >= 1
        assert stats.analysis_cycles >= 1
        assert stats.last_cursor is not None
        assert metrics.snapshot().completed == 2
        await engine.dispose()

    async def test_empty_second_turn_no_duplicate_analysis(self, tmp_path: Any) -> None:
        """Cursor ilerledi; yeni alert yok → faz başına tek analiz (çoğaltma yok)."""
        engine, maker = await _make_db(tmp_path, "loop2")
        source = _FixedSource(
            [make_alert(alert_id="910.1", timestamp=datetime.now(UTC) - timedelta(seconds=60))]
        )
        client = MockOllamaClient()
        analyzer = make_analyzer(client)
        stop = asyncio.Event()
        stats = WorkerLoopStats()

        loop_task = asyncio.create_task(
            run_worker_loop(
                maker,
                analyzer,
                stop_event=stop,
                interval_seconds=0.2,
                batch_size=10,
                metrics=AnalysisMetrics(),
                source=source,
                policy=POLICY,
                initial_window_seconds=3600,
                stats=stats,
            )
        )

        async def _second_turn_done() -> bool:
            return stats.iterations >= 2

        await _wait_until(_second_turn_done)
        stop.set()
        await asyncio.wait_for(loop_task, timeout=3.0)

        assert await _count(maker, Analysis) == 1
        assert len(client.calls) == 1  # ikinci turda model çağrısı YAPILMADI
        await engine.dispose()

    async def test_loop_survives_infrastructure_failure(self, tmp_path: Any) -> None:
        """Ollama kapalı turda döngü ÇÖKMEZ; sonraki turda pending analiz edilir."""
        engine, maker = await _make_db(tmp_path, "loop3")
        source = _FixedSource(
            [make_alert(alert_id="920.1", timestamp=datetime.now(UTC) - timedelta(seconds=60))]
        )
        # fail_first_n=2: tur 1'de analyzer'ın 2 denemesi de başarısız →
        # tur hatası kaydedilir; tur 2'de ilk deneme başarılı → analiz yazılır.
        client = MockOllamaClient(fail_first_n=2)
        analyzer = make_analyzer(client)
        stop = asyncio.Event()
        stats = WorkerLoopStats()

        loop_task = asyncio.create_task(
            run_worker_loop(
                maker,
                analyzer,
                stop_event=stop,
                interval_seconds=0.2,
                batch_size=10,
                metrics=AnalysisMetrics(),
                source=source,
                policy=POLICY,
                initial_window_seconds=3600,
                stats=stats,
            )
        )
        await _wait_until(_at_least(maker, Analysis, 1))
        stop.set()
        await asyncio.wait_for(loop_task, timeout=3.0)

        assert await _count(maker, Event) == 1
        assert await _count(maker, Analysis) == 1
        assert len(stats.errors) >= 1  # ilk turun hatası kaydedildi, döngü yaşadı
        await engine.dispose()


class TestDefaults:
    async def test_worker_loop_disabled_by_default(self, tmp_path: Any) -> None:
        """Güvenli başlangıç: döngü kapalı → arka plan task'ı YOK."""
        application = create_app(make_settings(tmp_path))
        assert application.state.worker_task is None

    async def test_worker_loop_starts_and_stops_cleanly(self, tmp_path: Any) -> None:
        """WORKER_LOOP_ENABLED=true → task başlar; lifespan kapanışı temiz biter.

        Faz 05 notu: lifespan artık startup bootstrap'ı içerir (users
        tablosuna bakar) → şema önce kurulur.
        """
        application = create_app(make_settings(tmp_path, worker_loop_enabled=True))
        from app.core.db import Base

        async with application.state.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with lifespan(application):
            task = application.state.worker_task
            assert task is not None
            assert not task.done()
        assert application.state.worker_task.done()
