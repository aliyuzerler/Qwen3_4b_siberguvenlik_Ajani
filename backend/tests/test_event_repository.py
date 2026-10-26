"""Idempotent depolama testleri (Faz 03) — sqlite+aiosqlite (gerçek DB yok).

Kapsam (phases/03 test promptu):
- duplicate event kontrolü (aynı olay çoğaltılmaz)
- aynı ID ile değişik payload (variant; ilk yazan kazanır)
- DB kesintisi (retryable hata, fail-fast)
- hassas alanların saklanan bağlamda maskeli olduğu (normalizer kanıtı + satır okuma)
- raw saklama yalnızca açıldığında
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from sqlalchemy import func, select

import app.models  # noqa: F401  # Event şemasını Base.metadata'ya kaydeder
from app.core.db import Base
from app.models.event import Event
from app.services.normalization.errors import StorageError
from app.services.normalization.models import NormalizedEvent
from app.services.normalization.normalizer import normalize_alert
from app.services.normalization.redaction import RedactionPolicy
from app.services.normalization.repository import (
    EventRepository,
    StoreOutcome,
    idempotency_key,
)
from tests.conftest import make_alert

POLICY = RedactionPolicy()


def _event(**overrides: object) -> NormalizedEvent:
    return normalize_alert(make_alert(**overrides), POLICY)


async def _row_count(maker: object) -> int:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    assert isinstance(maker, async_sessionmaker)
    async with maker() as session:
        return int(
            (await session.execute(select(func.count()).select_from(Event))).scalar_one()
        )


class TestIdempotencyKey:
    def test_key_is_deterministic_sha256(self) -> None:
        a = idempotency_key("wazuh", "1792974900.123456")
        b = idempotency_key("wazuh", "1792974900.123456")
        assert a == b
        assert len(a) == 64

    def test_key_differs_per_alert(self) -> None:
        assert idempotency_key("wazuh", "1") != idempotency_key("wazuh", "2")

    def test_key_differs_per_source(self) -> None:
        assert idempotency_key("wazuh", "1") != idempotency_key("other", "1")


class TestStoreEvent:
    async def test_new_event_stored(self, sessionmaker_fixture: object) -> None:
        repo = EventRepository(sessionmaker_fixture)  # type: ignore[arg-type]
        result = await repo.store_event(_event())
        assert result.outcome is StoreOutcome.STORED
        assert await _row_count(sessionmaker_fixture) == 1

    async def test_duplicate_does_not_create_row(self, sessionmaker_fixture: object) -> None:
        # "Tekrar gelen alert aynı olayı/analizi çoğaltmasın"
        repo = EventRepository(sessionmaker_fixture)  # type: ignore[arg-type]
        first = await repo.store_event(_event())
        second = await repo.store_event(_event())
        assert first.outcome is StoreOutcome.STORED
        assert second.outcome is StoreOutcome.DUPLICATE
        assert second.event_id == first.event_id  # aynı satır
        assert await _row_count(sessionmaker_fixture) == 1

    async def test_duplicate_increments_seen_count(self, sessionmaker_fixture: object) -> None:
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        repo = EventRepository(maker)
        await repo.store_event(_event())
        await repo.store_event(_event())
        async with maker() as session:
            row = (await session.execute(select(Event))).scalar_one()
        assert row.seen_count == 2
        assert row.last_seen_at is not None

    async def test_same_id_different_payload_keeps_first(
        self, sessionmaker_fixture: object
    ) -> None:
        # "aynı ID ile değişik payload": ilk yazan kazanır, satır değişmez.
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        repo = EventRepository(maker)
        first = await repo.store_event(_event(full_log="original content"))
        second = await repo.store_event(_event(full_log="changed content"))
        assert first.outcome is StoreOutcome.STORED
        assert second.outcome is StoreOutcome.VARIANT
        assert second.event_id == first.event_id
        assert await _row_count(maker) == 1
        async with maker() as session:
            row = (await session.execute(select(Event))).scalar_one()
        assert row.full_log_redacted == "original content"  # orijinal korunur
        assert row.variant_count == 1

    async def test_variant_does_not_change_rule_level(self, sessionmaker_fixture: object) -> None:
        # Orijinal severity korunur: variant gelse bile saklanan satır değişmez.
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        repo = EventRepository(maker)
        await repo.store_event(_event(rule_level=10))
        await repo.store_event(_event(rule_level=15, full_log="bambaşka içerik"))
        async with maker() as session:
            row = (await session.execute(select(Event))).scalar_one()
        assert row.rule_level == 10  # İLK değer (append-baskın)
        assert row.variant_count == 1

    async def test_original_fields_persisted(self, sessionmaker_fixture: object) -> None:
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        repo = EventRepository(maker)
        await repo.store_event(_event())
        async with maker() as session:
            row = (await session.execute(select(Event))).scalar_one()
        assert row.alert_id == "1792974900.123456"
        assert row.rule_level == 10
        assert row.rule_id == "5712"
        assert row.timestamp.tzinfo is not None
        assert row.idempotency_key == idempotency_key("wazuh", "1792974900.123456")

    async def test_secrets_not_in_stored_row(self, sessionmaker_fixture: object) -> None:
        # "secret'ların saklanan analiz bağlamında maskelenmesi"
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        repo = EventRepository(maker)
        await repo.store_event(_event(full_log="password=TopSecret456 src=203.0.113.7"))
        async with maker() as session:
            row = (await session.execute(select(Event))).scalar_one()
        assert row.full_log_redacted is not None
        assert "TopSecret456" not in row.full_log_redacted
        assert row.src_ip == "203.0.113.0"  # masked

    async def test_raw_stored_only_when_provided(self, sessionmaker_fixture: object) -> None:
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        repo = EventRepository(maker)
        await repo.store_event(_event())
        await repo.store_event(_event(alert_id="1792974900.777777"), raw={"id": "x"})
        async with maker() as session:
            rows = (await session.execute(select(Event))).scalars().all()
        raws = {r.alert_id: r.raw_alert for r in rows}
        assert raws["1792974900.123456"] is None  # varsayılan: ham saklanmaz
        assert raws["1792974900.777777"] == {"id": "x"}  # açıkça verilirse saklanır


class TestStoreBatch:
    async def test_batch_stores_all(self, sessionmaker_fixture: object) -> None:
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        repo = EventRepository(maker)
        events = [_event(alert_id=f"100.{i}") for i in range(3)]
        result = await repo.store_batch(events)
        assert result.stored == 3 and result.total_ok() == 3
        assert await _row_count(maker) == 3

    async def test_batch_duplicates_idempotent(self, sessionmaker_fixture: object) -> None:
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        repo = EventRepository(maker)
        events = [_event(alert_id=f"100.{i}") for i in range(3)]
        await repo.store_batch(events)
        again = await repo.store_batch(events)
        assert again.duplicate == 3 and again.stored == 0
        assert await _row_count(maker) == 3  # yeni satır YOK

    async def test_batch_isolates_non_retryable_failure(
        self, sessionmaker_fixture: object
    ) -> None:
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        repo = EventRepository(maker)
        events = [_event(alert_id=f"100.{i}") for i in range(3)]
        original = repo.store_event

        async def flaky(event: NormalizedEvent, **kwargs: object) -> object:
            if event.alert_id == "100.1":
                raise StorageError("kalıcı kısıt hatası", retryable=False)
            return await original(event, **kwargs)  # type: ignore[arg-type]

        with patch.object(repo, "store_event", side_effect=flaky):
            result = await repo.store_batch(events)
        assert result.stored == 2  # diğerleri saklandı (hata izolasyonu)
        assert result.failed == 1
        assert result.failures[0].alert_id == "100.1"
        assert result.failures[0].retryable is False

    async def test_batch_fails_fast_on_retryable_outage(
        self, sessionmaker_fixture: object
    ) -> None:
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        repo = EventRepository(maker)
        events = [_event(alert_id=f"100.{i}") for i in range(3)]

        async def outage(event: NormalizedEvent, **kwargs: object) -> object:
            raise StorageError("veritabanı erişilemiyor", retryable=True)

        with patch.object(repo, "store_event", side_effect=outage), pytest.raises(
            StorageError
        ) as excinfo:
            await repo.store_batch(events)
        assert excinfo.value.retryable is True  # fail-fast: batch devam etmez


class TestDbOutage:
    async def test_outage_raises_retryable_storage_error(self, tmp_path: object) -> None:
        from pathlib import Path

        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        assert isinstance(tmp_path, Path)
        # Var olmayan dizin → bağlantı/açılış hatası (deterministik kesinti simülasyonu)
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/no_such_dir/x.db")
        repo = EventRepository(async_sessionmaker(engine))
        try:
            with pytest.raises(StorageError) as excinfo:
                await repo.store_event(_event())
            assert excinfo.value.retryable is True
        finally:
            await engine.dispose()

    async def test_outage_does_not_persist_partial_state(self, tmp_path: object) -> None:
        from pathlib import Path

        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        assert isinstance(tmp_path, Path)
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/no_such_dir/y.db")
        repo = EventRepository(async_sessionmaker(engine))
        try:
            with pytest.raises(StorageError):
                await repo.store_event(_event())
        finally:
            await engine.dispose()
        # Yeniden çalışır durumda: aynı veri güvenle tekrar yazılabilir (idempotent).
        engine2 = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/recovered.db")
        async with engine2.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)  # toparlanmış şema
        repo2 = EventRepository(async_sessionmaker(engine2))
        try:
            result = await repo2.store_event(_event())
            assert result.outcome is StoreOutcome.STORED
        finally:
            await engine2.dispose()


class TestUtcTimestamps:
    async def test_received_at_is_utc_aware(self, sessionmaker_fixture: object) -> None:
        maker = sessionmaker_fixture  # type: ignore[arg-type]
        repo = EventRepository(maker)
        await repo.store_event(_event())
        async with maker() as session:
            row = (await session.execute(select(Event))).scalar_one()
        assert row.received_at.tzinfo is UTC
        assert abs((datetime.now(UTC) - row.received_at).total_seconds()) < 60
