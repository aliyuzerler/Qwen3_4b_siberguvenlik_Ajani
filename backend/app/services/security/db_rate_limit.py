"""Paylaşımlı (DB tabanlı) sabit pencere hız freni (Faz 08).

Gereksinim (phases/08: "rate limit ve DoS dayanıklılığı" + Faz 05/07
belgelenmiş sınırlama): çok prosesli uvicorn veya çok düğümlü dağıtımda
brute-force freninin prosesler ARASI geçerli olması.

Tasarım:
- Redis gibi yeni bir servis yerine MEVCUT DB kullanılır (stack sadeliği;
  AGENTS.md §2 öncelik 4). Gerektiğinde Redis'e geçiş config tek değişikliğidir.
- Sabit pencere: window_start = floor(now / window) * window. Kayan pencere
  yerine sabit pencere seçildi çünkü tek atomik UPSERT ile karar verilebilir
  (iki işlem aynı anda okuyup ikisi de izin veremez: RETURNING ile artan
  sayaç tek transaction'da gelir).
- ON CONFLICT DO UPDATE: PostgreSQL (asyncpg) ve SQLite (aiosqlite ≥3.24)
  desteklidir; dialect'e göre insert fonksiyonu seçilir.
- DB hatası: istisna yukarı fırlar (fail-closed). Kabul edilebilir: login
  zaten DB'siz çalışamaz; fren DB'den bağımsız çalışamaz.
- Cleanup: her check'te SOLE eski kova temizliği yapılmaz — pencere
  kapanmış kovalar, kendi anahtarının kontrolü sırasında silinir + global
  temizlik her N kontrolde bir (N=100; deterministik sayaç).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.rate_limit import RateLimitCounter
from app.services.security.rate_limit import RateLimitDecision

# Global cleanup sıklığı (kontrol sayacı; deterministik, test dostu).
CLEANUP_EVERY_N_CHECKS = 100


def _floor_window(now: datetime, window_seconds: float) -> datetime:
    """Pencere başlangıcına hizalı UTC zaman (floor)."""
    epoch = now.timestamp()
    window_start_epoch = (epoch // window_seconds) * window_seconds
    return datetime.fromtimestamp(window_start_epoch, tz=UTC)


class DatabaseRateLimiter:
    """(key, window_start) kovalarını DB'de tutan sabit pencere freni.

    - check() atomik UPSERT + RETURNING ile karar verir (yarış güvenli).
    - Retry-After: pencere bitişine kalan süre (en az 1 sn).
    - limit/window_rate: MemoryRateLimiter ile aynı anlamlar.
    """

    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        limit_per_minute: int,
        *,
        window_seconds: float = 60.0,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        if limit_per_minute < 1:
            raise ValueError("limit_per_minute en az 1 olmalıdır.")
        if window_seconds <= 0:
            raise ValueError("window_seconds pozitif olmalıdır.")
        self._sessionmaker = sessionmaker
        self._limit = limit_per_minute
        self._window = window_seconds
        self._now_fn = now_fn or (lambda: datetime.now(UTC))
        self._checks_since_cleanup = 0
        self._dialect_name: str | None = None

    @property
    def limit(self) -> int:
        return self._limit

    def _upsert_stmt(self, safe_key: str, window_start: datetime) -> Any:
        """Dialect'e göre atomik UPSERT+RETURNING (PostgreSQL/SQLite).

        Not: iki dialect'in Insert türleri farklı soyutlamadır; ortak
        Executable sözleşmesi üzerinden kullanıldığı için Any döner.
        """
        stmt: Any
        if self._dialect_name == "postgresql":
            stmt = pg_insert(RateLimitCounter).values(
                key=safe_key, window_start=window_start, hit_count=1
            )
        else:
            stmt = sqlite_insert(RateLimitCounter).values(
                key=safe_key, window_start=window_start, hit_count=1
            )
        return stmt.on_conflict_do_update(
            index_elements=[RateLimitCounter.key, RateLimitCounter.window_start],
            set_={"hit_count": RateLimitCounter.hit_count + 1},
        ).returning(RateLimitCounter.hit_count)

    async def check(self, key: str) -> RateLimitDecision:
        now = self._now_fn()
        window_start = _floor_window(now, self._window)
        window_end = window_start + timedelta(seconds=self._window)

        # Anahtar kolon sınırı altına kırpılır (IP audit ile aynı 64 kuralı).
        safe_key = key[:160]

        async with self._sessionmaker() as session:
            if self._dialect_name is None:
                bind = session.get_bind()
                self._dialect_name = bind.dialect.name
            row = (
                await session.execute(self._upsert_stmt(safe_key, window_start))
            ).first()
            await session.commit()
            hits = int(row[0]) if row is not None else 1

            self._checks_since_cleanup += 1
            if self._checks_since_cleanup >= CLEANUP_EVERY_N_CHECKS:
                self._checks_since_cleanup = 0
                cutoff = now - timedelta(seconds=self._window * 2)
                await session.execute(
                    delete(RateLimitCounter).where(
                        RateLimitCounter.window_start < cutoff
                    )
                )
                await session.commit()

        if hits > self._limit:
            retry_after = max(1, int((window_end - now).total_seconds()))
            return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)
        return RateLimitDecision(allowed=True)

    async def cleanup_stale(self) -> int:
        """Penceresi geçmiş TÜM kovaları siler (bakım/test yardımcısı).

        Döndürür: silinen satır sayısı (gözlemlenebilirlik testi için).
        """
        now = self._now_fn()
        cutoff = now - timedelta(seconds=self._window)
        async with self._sessionmaker() as session:
            result = await session.execute(
                delete(RateLimitCounter).where(RateLimitCounter.window_start < cutoff)
            )
            await session.commit()
            # DELETE sonuçları rowcount taşır (runtime); mypy Result tipinde
            # alanı görmediği için getattr ile güvenli okunur.
            return int(getattr(result, "rowcount", 0) or 0)

    async def snapshot(self) -> dict[str, int]:
        """Anahtar → güncel pencere içi isabet sayısı (test/gözlemlenebilirlik)."""
        from sqlalchemy import select

        current_window = _floor_window(self._now_fn(), self._window)
        async with self._sessionmaker() as session:
            result = await session.execute(
                select(RateLimitCounter.key, RateLimitCounter.hit_count).where(
                    RateLimitCounter.window_start >= current_window
                )
            )
            return {str(row[0]): int(row[1]) for row in result.all()}
