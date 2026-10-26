"""Dayanıklılık testleri (Faz 02): devre kesici + retry/backoff + Retry-After."""

from __future__ import annotations

import pytest

from app.services.wazuh.errors import (
    WazuhAuthError,
    WazuhRateLimitedError,
    WazuhUnavailableError,
)
from app.services.wazuh.resilience import (
    MAX_RETRY_AFTER_SECONDS,
    CircuitBreaker,
    run_with_retry,
)


class SleepRecorder:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


class FakeClock:
    """Kontrol edilebilir monotonik saat (kesici reset süresi simülasyonu)."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


# --- CircuitBreaker ------------------------------------------------------


async def test_breaker_opens_after_threshold() -> None:
    breaker = CircuitBreaker(failure_threshold=3, reset_seconds=30.0)
    for _ in range(3):
        await breaker.record_failure()
    assert breaker.state == CircuitBreaker.OPEN
    with pytest.raises(WazuhUnavailableError) as exc:
        await breaker.before_call()
    assert "devre kesici" in str(exc.value)


async def test_breaker_half_open_recovers_on_success() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(failure_threshold=1, reset_seconds=10.0, clock=clock)
    await breaker.record_failure()
    assert breaker.state == CircuitBreaker.OPEN
    clock.now = 10.0  # reset süresi doldu → yarım açık
    assert breaker.state == CircuitBreaker.HALF_OPEN
    await breaker.before_call()
    await breaker.record_success()
    assert breaker.state == CircuitBreaker.CLOSED


async def test_breaker_stays_open_until_reset_elapsed() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(failure_threshold=1, reset_seconds=30.0, clock=clock)
    await breaker.record_failure()
    assert breaker.state == CircuitBreaker.OPEN
    with pytest.raises(WazuhUnavailableError):
        await breaker.before_call()


async def test_breaker_half_open_failure_retrips() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(failure_threshold=1, reset_seconds=10.0, clock=clock)
    await breaker.record_failure()
    clock.now = 10.0  # yarım açık pencere
    assert breaker.state == CircuitBreaker.HALF_OPEN
    await breaker.record_failure()  # yarım açıkta hata → yeniden açık
    assert breaker.state == CircuitBreaker.OPEN
    with pytest.raises(WazuhUnavailableError):
        await breaker.before_call()


def test_breaker_invalid_threshold_rejected() -> None:
    with pytest.raises(ValueError):
        CircuitBreaker(failure_threshold=0, reset_seconds=1.0)


# --- run_with_retry ------------------------------------------------------


async def test_retry_respects_retry_after_header() -> None:
    sleep = SleepRecorder()
    calls: list[int] = []

    async def flaky() -> str:
        calls.append(1)
        if len(calls) == 1:
            raise WazuhRateLimitedError("oran sınırı", retry_after_seconds=2.0)
        return "ok"

    result = await run_with_retry(
        flaky, max_retries=3, backoff_base_seconds=10.0, sleep=sleep
    )
    assert result == "ok"
    assert len(calls) == 2
    # Retry-After (2s) üstel backoff'un (10s) yerine geçer → saygı kanıtı
    assert sleep.delays == [2.0]


async def test_retry_after_is_capped() -> None:
    sleep = SleepRecorder()

    async def always_limited() -> None:
        raise WazuhRateLimitedError("oran sınırı", retry_after_seconds=999.0)

    with pytest.raises(WazuhRateLimitedError):
        await run_with_retry(
            always_limited, max_retries=1, backoff_base_seconds=0.1, sleep=sleep
        )
    assert sleep.delays and sleep.delays[0] == MAX_RETRY_AFTER_SECONDS


async def test_non_retryable_error_not_retried() -> None:
    sleep = SleepRecorder()
    calls: list[int] = []

    async def forbidden() -> None:
        calls.append(1)
        raise WazuhAuthError("yetki hatası")

    with pytest.raises(WazuhAuthError):
        await run_with_retry(forbidden, max_retries=5, backoff_base_seconds=1.0, sleep=sleep)
    assert calls == [1]
    assert sleep.delays == []


async def test_retryable_error_exhausts_attempts_then_raises() -> None:
    sleep = SleepRecorder()
    calls: list[int] = []

    async def broken() -> None:
        calls.append(1)
        raise WazuhUnavailableError("5xx")

    with pytest.raises(WazuhUnavailableError):
        await run_with_retry(broken, max_retries=2, backoff_base_seconds=0.0, sleep=sleep)
    # ilk çağrı + 2 retry = 3 deneme
    assert len(calls) == 3
