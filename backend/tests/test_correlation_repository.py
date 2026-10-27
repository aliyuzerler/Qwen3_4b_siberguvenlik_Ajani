"""Korelasyon deposu testleri (Faz 06): idempotent kayıt, kanıt bağlantıları,
katalog senkronu, audit ve hata sınıflandırma (sqlite, DB yok)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.exc import OperationalError

import app.models  # noqa: F401  # metadata kaydı
from app.models.audit import AuditLog
from app.models.correlation import Correlation, CorrelationEvent, CorrelationRule
from app.models.event import Event
from app.services.correlation.engine import CorrelationDetection
from app.services.correlation.repository import (
    CorrelationRepository,
    SaveOutcome,
)
from app.services.correlation.rules import (
    CorrelationParams,
    CorrelationRuleDef,
    build_default_catalog,
)
from app.services.normalization.errors import StorageError
from app.services.security.audit import AuditAction

NOW = datetime(2026, 10, 26, 12, 30, 0, tzinfo=UTC)


async def _seed_rules(maker: Any, keys: list[str]) -> None:
    """FK hedefi: katalog satırları (üretimde startup senkronu yapar)."""
    async with maker() as session, session.begin():
        for key in keys:
            session.add(
                CorrelationRule(
                    key=key,
                    name=f"Kural {key}",
                    description="sentetik katalog satırı",
                    version=1,
                    kind="burst",
                    params={
                        "kind": "burst",
                        "window_seconds": 300.0,
                        "threshold": 5,
                        "group_by": ["agent_id"],
                    },
                    enabled=True,
                )
            )


def detection(**overrides: Any) -> CorrelationDetection:
    """SENTETİK tespit (5 olaylı burst; event ID'leri test içinde eklenir)."""
    values: dict[str, Any] = {
        "rule_key": "failed_login_burst",
        "rule_version": 1,
        "dedup_key": "d" * 64,
        "window_start": NOW - timedelta(minutes=5),
        "window_end": NOW - timedelta(minutes=3),
        "event_ids": tuple(),
        "event_count": 5,
        "max_rule_level": 10,
        "evidence": {
            "group_fields": ["agent_id"],
            "group_value": {"agent_id": "001"},
            "alert_ids": ["a1", "a2", "a3", "a4", "a5"],
        },
    }
    values.update(overrides)
    return CorrelationDetection(**values)


async def _store_events(
    maker: Any, count: int, *, agent_id: str = "001"
) -> list[Event]:
    events = []
    for i in range(count):
        row = Event(
            source="wazuh",
            alert_id=f"1792974900.{i:06d}",
            idempotency_key=f"key-{agent_id}-{i}",
            timestamp=NOW - timedelta(minutes=10 - i),
            rule_id="5710",
            rule_level=10,
            rule_description="sshd: Brute force",
            rule_groups=["authentication_failed"],
            agent_id=agent_id,
            agent_name="web-server-01",
            fingerprint=f"fp-{agent_id}-{i}",
        )
        events.append(row)
    async with maker() as session, session.begin():
        session.add_all(events)
    return events


class TestSaveDetection:
    async def test_new_detection_persists_row_and_links(
        self, sessionmaker_fixture: Any
    ) -> None:
        await _seed_rules(sessionmaker_fixture, ["failed_login_burst"])
        events = await _store_events(sessionmaker_fixture, 5)
        repo = CorrelationRepository(sessionmaker_fixture)
        det = detection(
            event_ids=tuple(str(e.id) for e in events),
            dedup_key="new-key-1",
        )
        result = await repo.save_detection(det, now=NOW)
        assert result.outcome == SaveOutcome.NEW
        async with sessionmaker_fixture() as session:
            row = (
                await session.scalars(
                    select(Correlation).where(Correlation.dedup_key == "new-key-1")
                )
            ).one()
            assert row.hit_count == 1
            assert row.event_count == 5
            assert row.max_rule_level == 10
            assert row.rule_key == "failed_login_burst"
            assert row.rule_version == 1
            link_count = (
                await session.execute(
                    select(func.count()).select_from(CorrelationEvent)
                )
            ).scalar_one()
        assert link_count == 5

    async def test_same_detection_again_is_hit_not_new_row(
        self, sessionmaker_fixture: Any
    ) -> None:
        await _seed_rules(sessionmaker_fixture, ["failed_login_burst"])
        events = await _store_events(sessionmaker_fixture, 5)
        repo = CorrelationRepository(sessionmaker_fixture)
        det = detection(event_ids=tuple(str(e.id) for e in events), dedup_key="dup-1")
        first = await repo.save_detection(det, now=NOW)
        second = await repo.save_detection(det, now=NOW + timedelta(seconds=30))
        assert first.outcome == SaveOutcome.NEW
        assert second.outcome == SaveOutcome.HIT
        assert second.correlation_id == first.correlation_id
        async with sessionmaker_fixture() as session:
            rows = (await session.scalars(select(Correlation))).all()
            assert len(rows) == 1  # tekrar YENİ SATIR ÜRETMEZ (duplicate yönetimi)
            assert rows[0].hit_count == 2
            assert rows[0].last_hit_at > rows[0].first_hit_at
            links = (
                await session.execute(
                    select(func.count()).select_from(CorrelationEvent)
                )
            ).scalar_one()
        assert links == 5  # bağlantılar çoğaltılmaz

    async def test_extended_cluster_links_new_events_only(
        self, sessionmaker_fixture: Any
    ) -> None:
        await _seed_rules(sessionmaker_fixture, ["failed_login_burst"])
        events = await _store_events(sessionmaker_fixture, 6)
        repo = CorrelationRepository(sessionmaker_fixture)
        first = detection(event_ids=tuple(str(e.id) for e in events[:5]), dedup_key="ext-1")
        await repo.save_detection(first, now=NOW)
        extended = detection(
            event_ids=tuple(str(e.id) for e in events), dedup_key="ext-1"
        )
        result = await repo.save_detection(extended, now=NOW + timedelta(seconds=60))
        assert result.outcome == SaveOutcome.HIT
        async with sessionmaker_fixture() as session:
            links = (
                await session.execute(
                    select(func.count()).select_from(CorrelationEvent)
                )
            ).scalar_one()
            row = (
                await session.scalars(
                    select(Correlation).where(Correlation.dedup_key == "ext-1")
                )
            ).one()
        assert links == 6  # yalnızca EKSİK bağlantı eklendi
        assert row.hit_count == 2

    async def test_different_dedup_key_creates_separate_row(
        self, sessionmaker_fixture: Any
    ) -> None:
        await _seed_rules(sessionmaker_fixture, ["failed_login_burst", "repeated_alert"])
        events = await _store_events(sessionmaker_fixture, 5)
        repo = CorrelationRepository(sessionmaker_fixture)
        ids = tuple(str(e.id) for e in events)
        await repo.save_detection(detection(event_ids=ids, dedup_key="k-1"), now=NOW)
        other = await repo.save_detection(
            detection(
                event_ids=ids,
                dedup_key="k-2",
                rule_key="repeated_alert",
            ),
            now=NOW,
        )
        assert other.outcome == SaveOutcome.NEW
        async with sessionmaker_fixture() as session:
            count = (
                await session.execute(select(func.count()).select_from(Correlation))
            ).scalar_one()
        assert count == 2

    async def test_event_delete_cascades_links(
        self, sessionmaker_fixture: Any
    ) -> None:
        await _seed_rules(sessionmaker_fixture, ["failed_login_burst"])
        events = await _store_events(sessionmaker_fixture, 3)
        repo = CorrelationRepository(sessionmaker_fixture)
        await repo.save_detection(
            detection(event_ids=tuple(str(e.id) for e in events), dedup_key="cas-1",
                      event_count=3),
            now=NOW,
        )
        async with sessionmaker_fixture() as session, session.begin():
            await session.execute(delete(Event).where(Event.id == events[0].id))
        async with sessionmaker_fixture() as session:
            links = (
                await session.execute(
                    select(func.count()).select_from(CorrelationEvent)
                )
            ).scalar_one()
        assert links == 2  # FK CASCADE: event retention bağlantıyı temizler

    async def test_storage_error_wrapped_retryable(
        self, sessionmaker_fixture: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = CorrelationRepository(sessionmaker_fixture)

        def _broken_maker(*args: Any, **kwargs: Any) -> Any:
            raise OperationalError("stmt", {}, Exception("bağlantı koptu"))

        monkeypatch.setattr(repo, "_sessionmaker", _broken_maker)
        with pytest.raises(StorageError, match="retryable=True"):
            await repo.save_detection(detection(dedup_key="err-1"), now=NOW)
        with pytest.raises(StorageError, match="retryable=True"):
            await repo.load_candidate_events(since=NOW, limit=10)


def _rule_def(key: str, version: int = 1, **param_overrides: Any) -> CorrelationRuleDef:
    params = CorrelationParams(
        kind="burst",
        window_seconds=300.0,
        threshold=5,
        group_by=["agent_id"],
        match_rule_groups=["authentication_failed"],
        **param_overrides,
    )
    return CorrelationRuleDef(
        key=key, name=f"Kural {key}", description="sentetik", version=version, params=params
    )


class TestRuleCatalogSync:
    async def test_initial_sync_creates_all_rules(
        self, sessionmaker_fixture: Any
    ) -> None:
        repo = CorrelationRepository(sessionmaker_fixture)
        result = await repo.sync_rule_catalog(build_default_catalog())
        assert sorted(result.created) == [
            "failed_login_burst",
            "repeated_alert",
            "suspicious_change_after_login",
        ]
        assert result.updated == []
        async with sessionmaker_fixture() as session:
            audit_count = (
                await session.execute(
                    select(func.count()).select_from(AuditLog).where(
                        AuditLog.action == AuditAction.CORRELATION_RULE_SYNCED
                    )
                )
            ).scalar_one()
        assert audit_count == 0  # ilk oluşturma sürüm değişimi değildir

    async def test_second_sync_is_unchanged(self, sessionmaker_fixture: Any) -> None:
        repo = CorrelationRepository(sessionmaker_fixture)
        await repo.sync_rule_catalog(build_default_catalog())
        result = await repo.sync_rule_catalog(build_default_catalog())
        assert result.created == []
        assert result.updated == []
        assert len(result.unchanged) == 3

    async def test_version_bump_updates_and_audits(
        self, sessionmaker_fixture: Any
    ) -> None:
        repo = CorrelationRepository(sessionmaker_fixture)
        await repo.sync_rule_catalog([_rule_def("kural_a"), _rule_def("kural_b")])
        bumped = [_rule_def("kural_a", version=2)]
        result = await repo.sync_rule_catalog(bumped)
        assert result.updated == ["kural_a"]
        async with sessionmaker_fixture() as session:
            row = await session.get(CorrelationRule, "kural_a")
            entries = (
                await session.scalars(
                    select(AuditLog).where(
                        AuditLog.action == AuditAction.CORRELATION_RULE_SYNCED
                    )
                )
            ).all()
        assert row is not None and row.version == 2
        assert len(entries) == 1
        assert entries[0].actor == "system"
        assert entries[0].detail == {"from_version": 1, "to_version": 2}

    async def test_sync_preserves_operator_enabled(
        self, sessionmaker_fixture: Any
    ) -> None:
        repo = CorrelationRepository(sessionmaker_fixture)
        await repo.sync_rule_catalog([_rule_def("kural_a")])
        # Operatör kuralı kapatır (admin PATCH'in yaptığı gibi):
        async with sessionmaker_fixture() as session, session.begin():
            row = await session.get(CorrelationRule, "kural_a")
            assert row is not None
            row.enabled = False
        # Yeni deploy sürüm artışıyla gelir; enabled KORUNUR:
        await repo.sync_rule_catalog([_rule_def("kural_a", version=2)])
        async with sessionmaker_fixture() as session:
            row = await session.get(CorrelationRule, "kural_a")
        assert row is not None and row.enabled is False and row.version == 2

    async def test_db_newer_version_not_downgraded(
        self, sessionmaker_fixture: Any
    ) -> None:
        repo = CorrelationRepository(sessionmaker_fixture)
        await repo.sync_rule_catalog([_rule_def("kural_a", version=3)])
        result = await repo.sync_rule_catalog([_rule_def("kural_a", version=1)])
        assert result.unchanged == ["kural_a"]
        async with sessionmaker_fixture() as session:
            row = await session.get(CorrelationRule, "kural_a")
        assert row is not None and row.version == 3


class TestLoadEnabledRules:
    async def test_disabled_rules_excluded(self, sessionmaker_fixture: Any) -> None:
        repo = CorrelationRepository(sessionmaker_fixture)
        await repo.sync_rule_catalog([_rule_def("aktif"), _rule_def("pasif")])
        async with sessionmaker_fixture() as session, session.begin():
            row = await session.get(CorrelationRule, "pasif")
            assert row is not None
            row.enabled = False
        result = await repo.load_enabled_rules()
        assert [r.key for r in result.rules] == ["aktif"]
        assert result.errors == []

    async def test_corrupt_params_row_skipped_with_error(
        self, sessionmaker_fixture: Any
    ) -> None:
        repo = CorrelationRepository(sessionmaker_fixture)
        await repo.sync_rule_catalog([_rule_def("aktif"), _rule_def("bozuk")])
        async with sessionmaker_fixture() as session, session.begin():
            row = await session.get(CorrelationRule, "bozuk")
            assert row is not None
            row.params = {"kind": "burst", "window_seconds": -1}  # geçersiz
        result = await repo.load_enabled_rules()
        assert [r.key for r in result.rules] == ["aktif"]  # tur düşmez, kural atlanır
        assert len(result.errors) == 1
        assert "bozuk" in result.errors[0]


async def _correlation_id(maker: Any) -> str:
    async with maker() as session:
        row = (await session.scalars(select(Correlation))).first()
        assert row is not None
        return str(row.id)


class TestUniqueConstraint:
    async def test_duplicate_dedup_key_rejected_at_db_level(
        self, sessionmaker_fixture: Any
    ) -> None:
        await _seed_rules(sessionmaker_fixture, ["failed_login_burst"])
        events = await _store_events(sessionmaker_fixture, 2)
        repo = CorrelationRepository(sessionmaker_fixture)
        await repo.save_detection(
            detection(event_ids=tuple(str(e.id) for e in events), dedup_key="u-1",
                      event_count=2),
            now=NOW,
        )
        # Doğrudan INSERT yolu (repository'siz) kısıt tarafından reddedilir:
        async with sessionmaker_fixture() as session, session.begin():
            session.add(
                Correlation(
                    rule_key="failed_login_burst",
                    rule_version=1,
                    dedup_key="u-1",
                    window_start=NOW,
                    window_end=NOW,
                    event_count=1,
                    max_rule_level=5,
                    evidence={},
                    hit_count=1,
                    first_hit_at=NOW,
                    last_hit_at=NOW,
                )
            )
            with pytest.raises(Exception):  # noqa: B017 — UNIQUE kısıtı
                await session.commit()
        assert await _correlation_id(sessionmaker_fixture)  # mevcut satır sağlam


