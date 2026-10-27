"""Bellek içi kayan pencere hız freni (Faz 05).

Kapsam: /auth/login ve /auth/refresh uçlarına IP başına dakikalık tavan
(brute-force freni; phases/05 "rate limit" gereksinimi).

Bilinçli sınırlama (belgelenmiş): sayaçlar uygulama belleğindedir ve tek
proses için geçerlidir. Compose dağıtımı tek backend prosesi çalıştırır;
Faz 08 (hardening) çok prosessli dağıtımda paylaşımlı depoya taşınacaktır.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Tek fren kararı (allowed=False ise retry_after dolu)."""

    allowed: bool
    retry_after_seconds: int = 0


class RateLimiter:
    """Anahtar başına kayan pencere sayacı.

    - check(): isteği kaydeder ve karar döner (atomiklik: tek olay döngüsü
      içinde senkron bölüm — await yok; asyncio altında yarış yok).
    - _hits sözlüğü zamanla büyümesin: her check'te süresi geçmiş girdiler
      budanır; ayrıca anahtar sayısı tavana ulaşınca en eski pencere atılır.
    """

    def __init__(self, limit_per_minute: int, *, window_seconds: float = 60.0) -> None:
        if limit_per_minute < 1:
            raise ValueError("limit_per_minute en az 1 olmalıdır.")
        self._limit = limit_per_minute
        self._window = window_seconds
        self._hits: dict[str, list[float]] = {}
        # Bellek tavanı: saldırıda anahtar patlamasını frenler (Faz 08 notu).
        self._max_keys = 10_000

    def check(self, key: str) -> RateLimitDecision:
        now = time.monotonic()
        window_start = now - self._window

        # Süresi geçmiş anahtarları tamamen at (bellek hijyeni)
        if len(self._hits) > self._max_keys:
            self._hits = {
                k: v for k, v in self._hits.items() if v and v[-1] > window_start
            }

        hits = self._hits.get(key)
        if hits is not None:
            while hits and hits[0] <= window_start:
                hits.pop(0)

        if hits is not None and len(hits) >= self._limit:
            retry_after = max(1, int(round(self._window - (now - hits[0]))))
            return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)

        if hits is None:
            if len(self._hits) >= self._max_keys:
                # Tavan dolu: en eski anahtarı düşür (adil olmayan ama güvenli)
                oldest = min(self._hits, key=lambda k: self._hits[k][-1] if self._hits[k] else 0.0)
                self._hits.pop(oldest, None)
            hits = []
            self._hits[key] = hits
        hits.append(now)
        return RateLimitDecision(allowed=True)

    def reset(self) -> None:
        """Tüm sayaçları temizler (test yardımcısı)."""
        self._hits.clear()

    @property
    def limit(self) -> int:
        return self._limit

    def snapshot(self) -> dict[str, Any]:
        """Test/gözlemlenebilirlik için sayaç anlık görüntüsü."""
        return {key: len(value) for key, value in self._hits.items()}
