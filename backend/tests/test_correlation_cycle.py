"""Korelasyon döngüsü testleri (Faz 06): aday yükleme → değerlendirme →
idempotent kayıt; kill switch, bozuk kural toleransı ve gecikme ölçümü."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select

from app.models.correlation import Correlation
from app.models.event import Event
from app.services.correlation.repository import CorrelationRepository
from app.services.normalization.errors import StorageError
from app.workers.correlation import run_correlation_cycle

NOW = datetime(2026, 10, 26, 12, 30, 0, tzinfo=UTC)


async def _store_failed_logins(
    maker: Any,
    *,
    count: int,
    start: datetime,
    agent_id: str = "001",
    interval_seconds: float = 30.0,
) -> None:
    rows = [
        Event(
            source="wazuh",
            alert_id=f"1792974900.{agent_id}.{i:04d}",
            idempotency_key=f"cycle-{agent_id}-{i}",
            timestamp=start + timedelta(seconds=i * interval_seconds),
            rule_id="5710",
            rule_level=10,
            rule_description="sshd: Brute force trying to get access to the system.",
            rule_groups=["syslog", "sshd", "authentication_failed"],
            agent_id=agent_id,
            agent_name="web-server-01" if agent_id == "001" else "db-server-01",
            fingerprint=f"cycle-fp-{agent_id}-{i}",
        )
        for i in range(count)
    ]
    async with maker() as session, session.begin():
        session.add_all(rows)


async def _correlation_stats(maker: Any) -> tuple[int, int]:
    async with maker() as session:
        total = int(
            (
                await session.execute(select(func.count()).select_from(Correlation))
            ).scalar_one()
        )
        hit_sum = int(
            (await session.execute(select(func.sum(Correlation.hit_count)))).scalar_one()
            or 0
        )
    return total, hit_sum


class TestCorrelationCycle:
    async def test_cycle_detects_burst_and_records(
        self, sessionmaker_fixture: Any
    ) -> None:
        maker = sessionmaker_fixture
        await CorrelationRepository(maker).sync_rule_catalog(
            __import__(
                "app.services.correlation.rules", fromlist=["build_default_catalog"]
            ).build_default_catalog()
        )
        await _store_failed_logins(maker, count=6, start=NOW - timedelta(minutes=4))
        result = await run_correlation_cycle(
            maker, lookback_seconds=3600.0, max_events=1000, now=NOW
        )
        assert result.events_scanned == 6
        assert result.detections_found >= 1
        assert result.new_correlations >= 1
        assert result.hits == 0
        assert result.max_latency_seconds > 0  # window_end < now → ölçülebilir
        total, hit_sum = await _correlation_stats(maker)
        assert total >= 1 and hit_sum >= 1

    async def test_second_cycle_hits_not_duplicates(
        self, sessionmaker_fixture: Any
    ) -> None:
        maker = sessionmaker_fixture
        from app.services.correlation.rules import build_default_catalog

        await CorrelationRepository(maker).sync_rule_catalog(build_default_catalog())
        await _store_failed_logins(maker, count=6, start=NOW - timedelta(minutes=4))
        first = await run_correlation_cycle(
            maker, lookback_seconds=3600.0, max_events=1000, now=NOW
        )
        second = await run_correlation_cycle(
            maker,
            lookback_seconds=3600.0,
            max_events=1000,
            now=NOW + timedelta(seconds=45),
        )
        assert first.new_correlations >= 1
        assert second.hits >= 1  # aynı pencere yeniden tespit edildi
        assert second.new_correlations == 0  # çoğaltma yok
        total, hit_sum = await _correlation_stats(maker)
        assert total == first.new_correlations  # satır sayısı sabit
        assert hit_sum > total  # hit_count arttı

    async def test_lookback_excludes_old_events(
        self, sessionmaker_fixture: Any
    ) -> None:
        maker = sessionmaker_fixture
        from app.services.correlation.rules import build_default_catalog

        await CorrelationRepository(maker).sync_rule_catalog(build_default_catalog())
        await _store_failed_logins(maker, count=6, start=NOW - timedelta(hours=8))
        result = await run_correlation_cycle(
            maker, lookback_seconds=3600.0, max_events=1000, now=NOW
        )
        assert result.events_scanned == 0
        assert result.detections_found == 0

    async def test_max_events_limit_caps_scan(
        self, sessionmaker_fixture: Any
    ) -> None:
        maker = sessionmaker_fixture
        from app.services.correlation.rules import build_default_catalog

        await CorrelationRepository(maker).sync_rule_catalog(build_default_catalog())
        await _store_failed_logins(maker, count=6, start=NOW - timedelta(minutes=4))
        result = await run_correlation_cycle(
            maker, lookback_seconds=3600.0, max_events=4, now=NOW
        )
        assert result.events_scanned == 4
        # Tarama tavanı ilk 4 olayı verir: failed_login_burst (eşik 5) ateşlemez;
        # repeated_alert (eşik 3, aynı agent+rule) ateşler.
        assert result.detections_found == 1

    async def test_disabled_rule_not_evaluated(
        self, sessionmaker_fixture: Any
    ) -> None:
        maker = sessionmaker_fixture
        repo = CorrelationRepository(maker)
        from app.services.correlation.rules import build_default_catalog

        await repo.sync_rule_catalog(build_default_catalog())
        # Operatör tüm kuralları kapatır:
        async with maker() as session, session.begin():
            from app.models.correlation import CorrelationRule

            rows = (await session.scalars(select(CorrelationRule))).all()
            for row in rows:
                row.enabled = False
        await _store_failed_logins(maker, count=6, start=NOW - timedelta(minutes=4))
        result = await run_correlation_cycle(
            maker, lookback_seconds=3600.0, max_events=1000, now=NOW
        )
        assert result.rules_evaluated == 0
        assert result.detections_found == 0

    async def test_corrupt_params_row_does_not_crash_cycle(
        self, sessionmaker_fixture: Any
    ) -> None:
        maker = sessionmaker_fixture
        repo = CorrelationRepository(maker)
        from app.services.correlation.rules import build_default_catalog

        await repo.sync_rule_catalog(build_default_catalog())
        async with maker() as session, session.begin():
            from app.models.correlation import CorrelationRule

            row = await session.get(CorrelationRule, "repeated_alert")
            assert row is not None
            row.params = {"kind": "burst", "window_seconds": "many"}  # bozuk
        await _store_failed_logins(maker, count=6, start=NOW - timedelta(minutes=4))
        result = await run_correlation_cycle(
            maker, lookback_seconds=3600.0, max_events=1000, now=NOW
        )
        assert any("repeated_alert" in err for err in result.rule_errors)
        # Diğer kurallar çalışmaya devam etti:
        assert result.detections_found >= 1

    async def test_retryable_storage_error_propagates(
        self, sessionmaker_fixture: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        maker = sessionmaker_fixture
        from app.services.correlation.rules import build_default_catalog

        await CorrelationRepository(maker).sync_rule_catalog(build_default_catalog())

        async def _db_down(self: Any, *, since: datetime, limit: int) -> list[Event]:
            raise StorageError("bağlantı koptu (sentetik)", retryable=True)

        monkeypatch.setattr(CorrelationRepository, "load_candidate_events", _db_down)
        # Altyapı hatası fail-fast yükseltilir (worker loop turu kaydeder,
        # döngü çökmez; sonraki tur aynı pencereyi güvenle yeniden tarar).
        with pytest.raises(StorageError, match="bağlantı koptu"):
            await run_correlation_cycle(
                maker, lookback_seconds=3600.0, max_events=1000, now=NOW
            )

    async def test_two_agents_two_correlations_in_one_cycle(
        self, sessionmaker_fixture: Any
    ) -> None:
        maker = sessionmaker_fixture
        from app.services.correlation.rules import build_default_catalog

        await CorrelationRepository(maker).sync_rule_catalog(build_default_catalog())
        await _store_failed_logins(
            maker, count=5, start=NOW - timedelta(minutes=4), agent_id="001"
        )
        await _store_failed_logins(
            maker, count=5, start=NOW - timedelta(minutes=4), agent_id="002"
        )
        result = await run_correlation_cycle(
            maker, lookback_seconds=3600.0, max_events=1000, now=NOW
        )
        # failed_login_burst ×2 (agent başına) + repeated_alert ×2 (aynı
        # agent+rule grupları): farklı sunucular BİRLEŞMEZ.
        assert result.new_correlations == 4
