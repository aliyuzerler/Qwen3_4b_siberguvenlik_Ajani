"""Alma döngüsü testleri (Faz 03): fetch → normalize → idempotent saklama.

Mock kaynak (sentetik fixture) + sqlite deposu kullanılır; gerçek Wazuh/PG yoktur.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import func, select

from app.models.event import Event
from app.services.normalization.errors import StorageError
from app.services.normalization.redaction import RedactionPolicy
from app.services.normalization.repository import EventRepository
from app.services.wazuh.errors import WazuhBadPayloadError
from app.services.wazuh.mock_source import MockWazuhAlertSource
from app.services.wazuh.models import AlertPage, AlertQuery
from app.workers.ingest import run_ingest_cycle
from tests.conftest import make_alert

POLICY = RedactionPolicy()


def _hit(alert_id: str, **source_overrides: Any) -> dict[str, Any]:
    """SENTETİK OpenSearch hit üretir (fixture biçiminde)."""
    source: dict[str, Any] = {
        "id": alert_id,
        "timestamp": "2026-10-26T09:15:00.000+0000",
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "sshd: Brute force trying to get access to the system.",
            "groups": ["syslog", "sshd"],
        },
        "agent": {"id": "001", "name": "web-server-01"},
        "data": {"srcip": "203.0.113.7"},
        "location": "/var/log/auth.log",
        "full_log": "Oct 26 09:15:00 sshd[4321]: Failed password for root",
    }
    source.update(source_overrides)
    return {"_id": alert_id, "_source": source}


async def _row_count(maker: Any) -> int:
    async with maker() as session:
        return int(
            (await session.execute(select(func.count()).select_from(Event))).scalar_one()
        )


class TestIngestCycle:
    async def test_full_cycle_stores_fixture_alerts(
        self, sessionmaker_fixture: Any
    ) -> None:
        source = MockWazuhAlertSource()
        repo = EventRepository(sessionmaker_fixture)
        result = await run_ingest_cycle(
            source, repo, POLICY, query=AlertQuery(limit=100)
        )
        assert result.fetched > 0
        assert result.stored == result.fetched
        assert result.failed == 0
        assert result.errors == []
        assert await _row_count(sessionmaker_fixture) == result.fetched

    async def test_second_cycle_does_not_duplicate(
        self, sessionmaker_fixture: Any
    ) -> None:
        # Çekirdek gereksinim: "Tekrar gelen alert aynı olayı/analizi çoğaltmasın."
        source = MockWazuhAlertSource()
        repo = EventRepository(sessionmaker_fixture)
        first = await run_ingest_cycle(source, repo, POLICY, query=AlertQuery(limit=100))
        second = await run_ingest_cycle(source, repo, POLICY, query=AlertQuery(limit=100))
        assert first.stored == first.fetched
        assert second.duplicate == first.fetched
        assert second.stored == 0
        assert await _row_count(sessionmaker_fixture) == first.fetched

    async def test_malformed_alert_isolated_not_fatal(
        self, sessionmaker_fixture: Any
    ) -> None:
        # Parse düzeyini (Faz 02) atlayan fake kaynak: normalizasyon hataları
        # (boş alert_id) döngüyü bloklamaz; sağlam alert'ler saklanır.
        good = make_alert(alert_id="1792974900.123456")
        broken = make_alert(alert_id="", rule_id="5712")  # normalizasyon reddeder

        class FakeSource:
            async def list_alerts(self, query: AlertQuery) -> AlertPage:
                return AlertPage(items=[broken, good], total=2, offset=0, limit=query.limit)

            async def get_alert(self, alert_id: str) -> Any:
                return None

            async def check_health(self) -> None:
                return None

            async def aclose(self) -> None:
                return None

        repo = EventRepository(sessionmaker_fixture)
        result = await run_ingest_cycle(
            FakeSource(),  # type: ignore[arg-type]
            repo,
            POLICY,
            query=AlertQuery(limit=100),
        )
        assert result.failed == 1  # bozuk alert izole edildi
        assert result.errors and "normalizasyon" in result.errors[0]
        assert result.stored == 1  # sağlam alert saklandı

    async def test_same_id_different_payload_becomes_variant(
        self, sessionmaker_fixture: Any
    ) -> None:
        repo = EventRepository(sessionmaker_fixture)
        await run_ingest_cycle(
            MockWazuhAlertSource(hits=[_hit("1792974900.123456")]),
            repo,
            POLICY,
            query=AlertQuery(limit=100),
        )
        result = await run_ingest_cycle(
            MockWazuhAlertSource(
                hits=[_hit("1792974900.123456", full_log="içerik değişti (sentetik)")]
            ),
            repo,
            POLICY,
            query=AlertQuery(limit=100),
        )
        assert result.variant == 1
        assert result.stored == 0
        assert await _row_count(sessionmaker_fixture) == 1  # çoğaltma yok

    async def test_pagination_multi_page(self, sessionmaker_fixture: Any) -> None:
        hits = [_hit(f"100.{i}") for i in range(5)]
        source = MockWazuhAlertSource(hits=hits)
        repo = EventRepository(sessionmaker_fixture)
        result = await run_ingest_cycle(
            source, repo, POLICY, query=AlertQuery(limit=2)
        )
        assert result.pages == 3  # 2+2+1
        assert result.fetched == 5
        assert result.stored == 5

    async def test_raw_stored_only_when_enabled(self, sessionmaker_fixture: Any) -> None:
        repo = EventRepository(sessionmaker_fixture)
        await run_ingest_cycle(
            MockWazuhAlertSource(),
            repo,
            POLICY,
            query=AlertQuery(limit=100),
            store_raw=False,
        )
        async with sessionmaker_fixture() as session:
            rows = (await session.execute(select(Event))).scalars().all()
        assert rows and all(r.raw_alert is None for r in rows)  # varsayılan: ham saklanmaz

    async def test_raw_stored_when_enabled(self, sessionmaker_fixture: Any) -> None:
        repo = EventRepository(sessionmaker_fixture)
        await run_ingest_cycle(
            MockWazuhAlertSource(),
            repo,
            POLICY,
            query=AlertQuery(limit=100),
            store_raw=True,
        )
        async with sessionmaker_fixture() as session:
            rows = (await session.execute(select(Event))).scalars().all()
        assert rows and all(r.raw_alert is not None for r in rows)

    async def test_db_outage_fails_fast(self, tmp_path: Any) -> None:
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/missing_dir/c.db")
        repo = EventRepository(async_sessionmaker(engine))
        try:
            with pytest.raises(StorageError) as excinfo:
                await run_ingest_cycle(
                    MockWazuhAlertSource(), repo, POLICY, query=AlertQuery(limit=100)
                )
            assert excinfo.value.retryable is True  # worker sonradan güvenle tekrar eder
        finally:
            await engine.dispose()

    async def test_source_error_propagates_unchanged(
        self, sessionmaker_fixture: Any
    ) -> None:
        # Kaynak hatası (ör. 401) depolama katmanına sızdırılmaz; olduğu gibi yükselir.
        source = MockWazuhAlertSource(error_queue=[WazuhBadPayloadError("bozuk yanıt (sentetik)")])
        repo = EventRepository(sessionmaker_fixture)
        with pytest.raises(WazuhBadPayloadError):
            await run_ingest_cycle(source, repo, POLICY, query=AlertQuery(limit=100))
        assert await _row_count(sessionmaker_fixture) == 0
