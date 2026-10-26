"""Dayanıklılık ilkeleri: devre kesici + sınırlı retry/backoff (Faz 02).

Kurallar (phases/02-wazuh-integration.md, AGENTS.md §8):
- Timeout, sınırlı retry/backoff, circuit breaker uygulanır.
- Retry-After başlığına saygı gösterilir (tavanla sınırlı).
- 401/403 ve bozuk gövde tekrar denemez; yalnızca geçici hatalar denenebilir.

Test edilebilirlik: uyku fonksiyonu ve saat dışarıdan enjekte edilir;
testler gerçek bekleme yapmadan davranışı doğrular.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable

from app.services.wazuh.errors import WazuhError, WazuhUnavailableError

# Retry-After tavanı: kötü niyetli/hatalı büyük değerlere karşı koruma
MAX_RETRY_AFTER_SECONDS = 15.0

AsyncSleep = Callable[[float], Awaitable[None]]
Clock = Callable[[], float]


class CircuitBreaker:
    """Basit async devre kesici: closed → open → (reset süresi sonra) half_open.

    - closed: çağrılara izin var; hata eşiği aşılırsa open'a geçer.
    - open: çağrılar anında reddedilir; reset_seconds sonra half_open olur.
    - half_open: tek başarılı çağrı closed'a döndürür; başarısızlık yeniden open.
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(
        self,
        failure_threshold: int,
        reset_seconds: float,
        *,
        clock: Clock | None = None,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold en az 1 olmalıdır.")
        self._threshold = failure_threshold
        self._reset_seconds = reset_seconds
        self._clock: Clock = clock or _default_clock
        self._lock = asyncio.Lock()
        self._state = self.CLOSED
        self._failure_count = 0
        self._opened_at: float | None = None

    @property
    def state(self) -> str:
        if (
            self._state == self.OPEN
            and self._opened_at is not None
            and self._clock() - self._opened_at >= self._reset_seconds
        ):
            return self.HALF_OPEN
        return self._state

    async def before_call(self) -> None:
        """Çağrı öncesi izin kontrolü; açık kesici WazuhUnavailableError fırlatır."""
        async with self._lock:
            state = self.state
            if state == self.OPEN:
                raise WazuhUnavailableError(
                    "Wazuh devre kesici açık: servis istemci tarafından geçici "
                    "olarak durduruldu; reset süresi sonunda yeniden denenecek."
                )
            if state == self.HALF_OPEN:
                self._state = self.HALF_OPEN

    async def record_success(self) -> None:
        async with self._lock:
            self._state = self.CLOSED
            self._failure_count = 0
            self._opened_at = None

    async def record_failure(self) -> None:
        async with self._lock:
            if self.state == self.HALF_OPEN:
                self._trip()
                return
            if self._state == self.CLOSED:
                self._failure_count += 1
                if self._failure_count >= self._threshold:
                    self._trip()

    def _trip(self) -> None:
        self._state = self.OPEN
        self._opened_at = self._clock()
        self._failure_count = 0


def _default_clock() -> float:
    return asyncio.get_running_loop().time()


async def run_with_retry[T](
    operation: Callable[[], Awaitable[T]],
    *,
    max_retries: int,
    backoff_base_seconds: float,
    sleep: AsyncSleep | None = None,
) -> T:
    """Operasyonu sınırlı kez, üstel backoff + jitter ile tekrarlar.

    - Yalnızca `retryable=True` hatalar tekrar denenir.
    - 429 + Retry-After varsa backoff yerine Retry-After (tavanlı) beklenir.
    - Deneme sayısı: ilk çağrı + max_retries.
    """
    do_sleep: AsyncSleep = sleep or asyncio.sleep
    attempts = max_retries + 1
    last_error: WazuhError | None = None

    for attempt in range(attempts):
        if attempt > 0:
            assert last_error is not None  # noqa: S101 — döngü garantisi
            delay = backoff_base_seconds * (2 ** (attempt - 1)) + random.uniform(  # noqa: S311
                0, backoff_base_seconds * 0.25
            )
            retry_after = getattr(last_error, "retry_after_seconds", None)
            if retry_after is not None:
                delay = min(retry_after, MAX_RETRY_AFTER_SECONDS)
            await do_sleep(delay)

        try:
            return await operation()
        except WazuhError as exc:
            if not exc.retryable or attempt == attempts - 1:
                raise
            last_error = exc

    raise AssertionError("erişilemez")  # pragma: no cover
