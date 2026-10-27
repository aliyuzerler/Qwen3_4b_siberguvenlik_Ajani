"""Paylaşımlı (DB tabanlı) hız freni testleri (Faz 08).

Kapsam (phases/08: "rate limit ve DoS dayanıklılığı"):
- Sabit pencere: limit dolana kadar izin, aşımında ret + Retry-After.
- Paylaşımlılık: AYRI DatabaseRateLimiter örnekleri (farklı oturum
  fabrikaları, AYNI DB dosyası) aynı sayacı görür — çok proses simülasyonu.
- Pencere rollover: enjekte edilen saat ile pencere bitişi yeni sayfa açar.
- Cleanup: penceresi geçmiş kovalar silinir (bellek/disk hijyeni).
- Anahtar izolasyonu: farklı anahtarlar birbirini etkilemez.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.models  # noqa: F401  # RateLimitCounter'ı metadata'ya kaydeder
from app.core.db import Base, register_sqlite_fk_pragma
from app.services.security.db_rate_limit import DatabaseRateLimiter


@pytest.fixture
async def shared_db(tmp_path: Path):
    """İki proses simülasyonu: aynı sqlite dosyasına iki sessionmaker."""
    db_url = f"sqlite+aiosqlite:///{tmp_path}/shared.db"
    engines = []
    makers = []
    for _ in range(2):
        engine = create_async_engine(db_url)
        register_sqlite_fk_pragma(engine)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        engines.append(engine)
        makers.append(async_sessionmaker(engine, expire_on_commit=False))
    try:
        yield makers
    finally:
        for engine in engines:
            await engine.dispose()


class TestDatabaseRateLimiter:
    async def test_allows_up_to_limit(self, shared_db) -> None:
        limiter = DatabaseRateLimiter(shared_db[0], 3)
        for _ in range(3):
            decision = await limiter.check("login:203.0.113.9")
            assert decision.allowed

    async def test_blocks_after_limit_with_retry_after(self, shared_db) -> None:
        limiter = DatabaseRateLimiter(shared_db[0], 2)
        await limiter.check("login:203.0.113.9")
        await limiter.check("login:203.0.113.9")
        blocked = await limiter.check("login:203.0.113.9")
        assert not blocked.allowed
        assert blocked.retry_after_seconds >= 1
        assert blocked.retry_after_seconds <= 60

    async def test_counters_shared_across_instances(self, shared_db) -> None:
        """Çok proses simülasyonu: iki ayrı limiter (iki oturum fabrikası)."""
        limiter_a = DatabaseRateLimiter(shared_db[0], 2)
        limiter_b = DatabaseRateLimiter(shared_db[1], 2)
        assert (await limiter_a.check("login:198.51.100.4")).allowed
        assert (await limiter_b.check("login:198.51.100.4")).allowed
        # A instance'ı B'nin kaydettiğini GÖRÜR (paylaşımlı depo)
        blocked = await limiter_a.check("login:198.51.100.4")
        assert not blocked.allowed

    async def test_keys_are_isolated(self, shared_db) -> None:
        limiter = DatabaseRateLimiter(shared_db[0], 1)
        await limiter.check("login:198.51.100.4")
        assert not (await limiter.check("login:198.51.100.4")).allowed
        assert (await limiter.check("login:198.51.100.5")).allowed

    async def test_window_rollover_resets_counter(self, shared_db, tmp_path: Path) -> None:
        """Enjekte edilmiş saat: pencere dolduğunda sayaç yeni sayfa açar."""
        fixed_now = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)
        tick = {"now": fixed_now}

        def clock() -> datetime:
            return tick["now"]

        limiter = DatabaseRateLimiter(shared_db[0], 1, window_seconds=60.0, now_fn=clock)
        assert (await limiter.check("login:198.51.100.4")).allowed
        blocked = await limiter.check("login:198.51.100.4")
        assert not blocked.allowed
        # Pencere ötesine ilerle (61 sn): yeni kova → izin
        tick["now"] = fixed_now + timedelta(seconds=61)
        assert (await limiter.check("login:198.51.100.4")).allowed

    async def test_retry_after_decreases_with_window_progress(self, shared_db) -> None:
        fixed_now = datetime(2026, 10, 27, 12, 0, 30, tzinfo=UTC)
        tick = {"now": fixed_now}
        limiter = DatabaseRateLimiter(
            shared_db[0], 1, window_seconds=60.0, now_fn=lambda: tick["now"]
        )
        await limiter.check("login:198.51.100.4")
        blocked = await limiter.check("login:198.51.100.4")
        assert not blocked.allowed
        # Pencere başlangıcı 12:00:00; şimdi 12:00:30 → kalan ~30 sn
        assert blocked.retry_after_seconds <= 31
        assert blocked.retry_after_seconds >= 29

    async def test_cleanup_stale_removes_old_buckets(self, shared_db) -> None:
        fixed_now = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)
        tick = {"now": fixed_now}
        limiter = DatabaseRateLimiter(
            shared_db[0], 5, window_seconds=60.0, now_fn=lambda: tick["now"]
        )
        await limiter.check("login:198.51.100.4")
        tick["now"] = fixed_now + timedelta(seconds=120)
        removed = await limiter.cleanup_stale()
        assert removed == 1
        snapshot = await limiter.snapshot()
        assert "login:198.51.100.4" not in snapshot

    async def test_snapshot_reflects_current_window(self, shared_db) -> None:
        limiter = DatabaseRateLimiter(shared_db[0], 5)
        await limiter.check("login:198.51.100.4")
        await limiter.check("login:198.51.100.4")
        await limiter.check("login:198.51.100.5")
        snapshot = await limiter.snapshot()
        assert snapshot["login:198.51.100.4"] == 2
        assert snapshot["login:198.51.100.5"] == 1

    async def test_long_key_truncated_safely(self, shared_db) -> None:
        limiter = DatabaseRateLimiter(shared_db[0], 1)
        long_key = "login:" + "a" * 500
        assert (await limiter.check(long_key)).allowed
        assert not (await limiter.check(long_key)).allowed

    async def test_invalid_construction_rejected(self, shared_db) -> None:
        with pytest.raises(ValueError):
            DatabaseRateLimiter(shared_db[0], 0)
        with pytest.raises(ValueError):
            DatabaseRateLimiter(shared_db[0], 5, window_seconds=0.0)
