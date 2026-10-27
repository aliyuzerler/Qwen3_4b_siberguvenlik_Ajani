"""Kayan pencere hız freni testleri (Faz 05)."""

from __future__ import annotations

from app.services.security.rate_limit import RateLimiter


class TestRateLimiter:
    def test_allows_up_to_limit(self) -> None:
        limiter = RateLimiter(5)
        decisions = [limiter.check("ip-a").allowed for _ in range(5)]
        assert all(decisions)

    def test_blocks_after_limit_with_retry_after(self) -> None:
        limiter = RateLimiter(3)
        for _ in range(3):
            assert limiter.check("ip-a").allowed
        blocked = limiter.check("ip-a")
        assert not blocked.allowed
        assert blocked.retry_after_seconds >= 1
        assert blocked.retry_after_seconds <= 60

    def test_keys_are_isolated(self) -> None:
        limiter = RateLimiter(2)
        limiter.check("ip-a")
        limiter.check("ip-a")
        assert not limiter.check("ip-a").allowed
        # Farklı anahtar etkilenmez
        assert limiter.check("ip-b").allowed

    def test_reset_clears_state(self) -> None:
        limiter = RateLimiter(1)
        limiter.check("ip-a")
        limiter.reset()
        assert limiter.check("ip-a").allowed

    def test_zero_limit_rejected_at_construction(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            RateLimiter(0)

    def test_snapshot_reflects_counts(self) -> None:
        limiter = RateLimiter(10)
        limiter.check("ip-a")
        limiter.check("ip-a")
        limiter.check("ip-b")
        snapshot = limiter.snapshot()
        assert snapshot == {"ip-a": 2, "ip-b": 1}
