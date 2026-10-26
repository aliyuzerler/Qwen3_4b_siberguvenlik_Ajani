"""Analiz döngüsü: pending seç → analiz → append-only kayıt (Faz 04).

Kurallar:
- Event başına hata izolasyonu: tek event'in analysis_failed sonucu
  diğerlerini engellemez; tek event'in KALICI DB yazım hatası izole edilir.
- Retryable DB hatası fail-fast yükseltilir (Faz 03 depo disiplini).
- Ollama/altyapı hatası (analyzer yükseltir) → döngü DERHAL durur;
  analyses tablosuna satır YAZILMAZ; event'ler pending kalır ve sonraki
  döngüde tekrar denenir (idempotent pending seçimi sayesinde güvenli).
- Model çıktı hatası → analysis_failed SATIRI yazılır (güvenli fallback,
  AGENTS.md §5) ve metrikler kaydedilir.
- Eşzamanlılık: analyzer içindeki Semaphore ile sınırlandırılır (config:
  WORKER_CONCURRENCY).

Ölçüm (phases/04 doğrulama): metrics enjekte edilirse her sonuç kaydedilir;
snapshot ile schema geçerlilik oranı / p50 / p95 / hata oranı raporlanır.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.services.analysis.analyzer import AnalysisOutcome, EventAnalyzer
from app.services.analysis.errors import AnalysisError
from app.services.analysis.metrics import AnalysisMetrics
from app.services.analysis.repository import AnalysisRepository
from app.services.normalization.errors import StorageError


@dataclass
class AnalysisCycleResult:
    """Tek analiz döngüsünün ölçülebilir sonucu (başarı ölçütü, AGENTS.md §7)."""

    pending_seen: int = 0
    completed: int = 0
    failed: int = 0  # analysis_failed satırları (güvenli fallback)
    skipped: int = 0  # yarış kaybı (analiz zaten var)
    db_errors: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def processed(self) -> int:
        return self.completed + self.failed + self.skipped


async def run_analysis_cycle(
    sessionmaker: async_sessionmaker[AsyncSession],
    analyzer: EventAnalyzer,
    *,
    batch_size: int,
    metrics: AnalysisMetrics | None = None,
    now: datetime | None = None,
) -> AnalysisCycleResult:
    """Bekleyen event'leri analiz eder ve kaydeder.

    Altyapı hatasında (Ollama erişilemez / model yok / DB kopuk) hata
    YÜKSELTİR — çağıran (worker loop) loglayıp sonraki aralıkta tekrar dener.
    """
    repository = AnalysisRepository(sessionmaker)
    result = AnalysisCycleResult()
    pending = await repository.select_pending_events(limit=batch_size)
    result.pending_seen = len(pending)

    for item in pending:
        try:
            outcome = await analyzer.analyze(item.context)
        except AnalysisError as exc:
            # Altyapı ailesi: fail-fast — kalan event'ler pending kalır.
            result.errors.append(f"analiz altyapı hatası: {exc.message}")
            raise
        if metrics is not None:
            metrics.record(outcome)
        try:
            save = await repository.save_outcome(outcome)
        except StorageError as exc:
            if exc.retryable:
                raise
            result.db_errors += 1
            result.errors.append(f"depolama: {item.event_id} ({exc.message})")
            continue
        if save.status == "skipped":
            # Yarış kaybı: analiz zaten vardı; çoğaltma sayılmaz.
            result.skipped += 1
        else:
            _record_outcome(result, outcome)

    return result


def _record_outcome(result: AnalysisCycleResult, outcome: AnalysisOutcome) -> None:
    if outcome.status == "completed":
        result.completed += 1
    else:
        result.failed += 1


def utc_now() -> datetime:
    """Döngü zaman damgası (UTC; testlerde enjeksiyon için ayrı fonksiyon)."""
    return datetime.now(UTC)


__all__ = ["AnalysisCycleResult", "run_analysis_cycle", "utc_now"]
