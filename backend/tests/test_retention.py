"""Retention purge testleri (Faz 03).

Gereksinim: "DB migration, indeksler, retention ayarı" — varsayılan 30 gün,
AGENTS.md §6 gereği yapılandırılabilir. SQLite ile gerçek DELETE yolu test edilir.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.models.event import Event
from app.services.normalization.normalizer import normalize_alert
from app.services.normalization.redaction import RedactionPolicy
from app.services.normalization.repository import purge_expired_events
from tests.conftest import make_alert

POLICY = RedactionPolicy()
NOW = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)


def _normalized_at(ts: datetime, alert_id: str) -> object:
    return normalize_alert(make_alert(alert_id=alert_id, timestamp=ts), POLICY)


async def _store_at(maker: object, alert_id: str, ts: datetime) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.services.normalization.repository import EventRepository

    assert isinstance(maker, async_sessionmaker)
    repo = EventRepository(maker)
    await repo.store_event(_normalized_at(ts, alert_id))  # type: ignore[arg-type]


class TestPurgeExpiredEvents:
    async def test_purges_only_older_than_cutoff(self, sessionmaker_fixture: object) -> None:
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        old_ts = NOW - timedelta(days=40)
        recent_ts = NOW - timedelta(days=1)
        await _store_at(maker, "old", old_ts)
        await _store_at(maker, "recent", recent_ts)

        deleted = await purge_expired_events(maker, now=NOW, days=30)

        assert deleted == 1
        async with maker() as session:
            remaining = (await session.execute(select(Event))).scalars().all()
        assert len(remaining) == 1
        assert remaining[0].timestamp == recent_ts

    async def test_purge_default_thirty_days_boundary(self, sessionmaker_fixture: object) -> None:
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        edge_old = NOW - timedelta(days=30, seconds=1)  # sınırın dışında → silinir
        edge_new = NOW - timedelta(days=30, seconds=-1)  # sınır içinde → kalır
        await _store_at(maker, "edge-old", edge_old)
        await _store_at(maker, "edge-new", edge_new)

        deleted = await purge_expired_events(maker, now=NOW, days=30)
        assert deleted == 1

    async def test_purge_on_empty_table_is_zero(self, sessionmaker_fixture: object) -> None:
        deleted = await purge_expired_events(sessionmaker_fixture, now=NOW, days=30)  # type: ignore[arg-type]
        assert deleted == 0

    async def test_purge_is_idempotent(self, sessionmaker_fixture: object) -> None:
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        await _store_at(maker, "old", NOW - timedelta(days=60))
        first = await purge_expired_events(maker, now=NOW, days=30)
        second = await purge_expired_events(maker, now=NOW, days=30)
        assert first == 1 and second == 0
