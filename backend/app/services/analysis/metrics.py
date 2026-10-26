"""Analiz ölçüm takibi (Faz 04) — "Başarıyı varsayma; ölçüm sonucu ver."

Gereksinim (phases/04 doğrulama promptu): "JSON schema geçerlilik oranı,
p50/p95 latency ve hata oranını raporla."

Kapsam: süreç içi, basit kümülatif sayaçlar (Faz 09'da kalıcı/metrik
backend'ine taşınacaktır). Tek asyncio döngüsünde çalıştığı için
kilit gerektirmez; snapshot anlık tutarlılıktır.

Tanımlar (AGENTS.md §7 başarı ölçütleriyle hizalı):
- schema_valid_rate = completed / total      (tamamlanan / tüm sonuçlar)
- error_rate        = analysis_failed / total
- latency           = her completed+failed sonucun duration_ms'i
- p50/p95           = en yakın rütbe (nearest-rank) yüzdeleme; boş veride 0
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from app.services.analysis.analyzer import AnalysisOutcome


@dataclass(frozen=True)
class MetricsSnapshot:
    """Ölçüm anlık görüntüsü (raporlama/panel için)."""

    total: int
    completed: int
    failed: int
    schema_valid_rate: float  # 0.0-1.0
    error_rate: float  # 0.0-1.0
    p50_ms: int
    p95_ms: int
    retries_total: int

    def as_dict(self) -> dict[str, int | float]:
        return {
            "total": self.total,
            "completed": self.completed,
            "failed": self.failed,
            "schema_valid_rate": round(self.schema_valid_rate, 4),
            "error_rate": round(self.error_rate, 4),
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "retries_total": self.retries_total,
        }


def _nearest_rank_percentile(sorted_values: list[int], percentile: float) -> int:
    """En yakın rütbe yöntemi (nearest-rank): p = ceil(P/100 * N), 1-indexli."""
    if not sorted_values:
        return 0
    rank = math.ceil(percentile / 100 * len(sorted_values))
    return sorted_values[max(0, min(rank - 1, len(sorted_values) - 1))]


class AnalysisMetrics:
    """Kümülatif analiz sonuç sayaçları (süreç içi)."""

    def __init__(self) -> None:
        self._total = 0
        self._completed = 0
        self._failed = 0
        self._durations_ms: list[int] = []
        self._retries_total = 0

    def record(self, outcome: AnalysisOutcome) -> None:
        """Bir AnalysisOutcome kaydeder (yalnızca sonuç aileleri)."""
        if outcome.status == "completed":
            self._completed += 1
        elif outcome.status == "analysis_failed":
            self._failed += 1
        else:  # pragma: no cover — bilinmeyen durum sessizce sayılmaz
            return
        self._total += 1
        self._durations_ms.append(outcome.metadata.duration_ms)
        self._retries_total += outcome.metadata.retries_used

    def snapshot(self) -> MetricsSnapshot:
        durations = sorted(self._durations_ms)
        total = self._total
        return MetricsSnapshot(
            total=total,
            completed=self._completed,
            failed=self._failed,
            schema_valid_rate=(self._completed / total) if total else 0.0,
            error_rate=(self._failed / total) if total else 0.0,
            p50_ms=_nearest_rank_percentile(durations, 50),
            p95_ms=_nearest_rank_percentile(durations, 95),
            retries_total=self._retries_total,
        )


__all__ = ["AnalysisMetrics", "MetricsSnapshot"]
