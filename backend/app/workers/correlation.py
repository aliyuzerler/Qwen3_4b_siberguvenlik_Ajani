"""Korelasyon döngüsü (Faz 06): aday yükle → değerlendir → idempotent kaydet.

Kurallar:
- DB'den ETKİN kurallar okunur (admin toggle anında geçerli olur; koddaki
  katalog yalnızca seed/senkron kaynağıdır).
- Bozuk params satırı turu DÜŞÜRMEZ: hata raporlanır, o kural atlanır
  (savunma derinliği; normal yolda params Pydantic ile doğrulanmış olur).
- DB altyapı hatası StorageError(retryable=True) yükseltir → worker loop
  fail-fast yapar, döngü ÇÖKMEZ (Faz 04 kalıbı); aynı pencere idempotent
  yeniden taranabilir (dedup_key).
- Tespit başına kayıt hatası (non-retryable) izole edilir; diğer tespitler
  kaydedilmeye devam eder.
- Ölçüm: event→tespit gecikmesi (latency) detection.latency_seconds(now)
  ile hesaplanır; tespit başına loglanır (phases/06 doğrulama ölçütü).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.logging import get_logger
from app.services.correlation.engine import CorrelationEngine
from app.services.correlation.repository import CorrelationRepository, SaveOutcome
from app.services.normalization.errors import StorageError

logger = get_logger(__name__)


@dataclass
class CorrelationCycleResult:
    """Tek korelasyon turunun ölçülebilir sonucu (AGENTS.md §7)."""

    events_scanned: int = 0
    rules_evaluated: int = 0
    detections_found: int = 0
    new_correlations: int = 0
    hits: int = 0  # mevcut tespitin tekrar görünmesi (yeni satır YOK)
    skipped_missing_group: int = 0
    rule_errors: list[str] = field(default_factory=list)
    save_errors: list[str] = field(default_factory=list)
    max_latency_seconds: float = 0.0
    duration_ms: int = 0


async def run_correlation_cycle(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    lookback_seconds: float,
    max_events: int,
    now: datetime | None = None,
    engine: CorrelationEngine | None = None,
) -> CorrelationCycleResult:
    """Tek tur: lookback penceresini tarar, tespitleri idempotent kaydeder."""
    current = now or datetime.now(UTC)
    started = time.monotonic()
    repository = CorrelationRepository(sessionmaker)
    result = CorrelationCycleResult()

    enabled = await repository.load_enabled_rules()
    result.rule_errors.extend(enabled.errors)

    events = await repository.load_candidate_events(
        since=current - timedelta(seconds=lookback_seconds), limit=max_events
    )
    result.events_scanned = len(events)

    run = (engine or CorrelationEngine()).evaluate(
        events, [rule for rule in enabled.rules]
    )
    result.rules_evaluated = run.rules_evaluated
    result.skipped_missing_group = run.skipped_missing_group
    result.detections_found = len(run.detections)

    for detection in run.detections:
        latency = detection.latency_seconds(now=current)
        result.max_latency_seconds = max(result.max_latency_seconds, latency)
        try:
            save = await repository.save_detection(detection, now=current)
        except StorageError as exc:
            if exc.retryable:
                raise  # altyapı hatası: fail-fast (worker loop yeniden dener)
            result.save_errors.append(f"{detection.rule_key}: {exc.message}")
            continue
        if save.outcome == SaveOutcome.NEW:
            result.new_correlations += 1
        else:
            result.hits += 1
        logger.info(
            "correlation_detection_saved",
            rule_key=detection.rule_key,
            rule_version=detection.rule_version,
            outcome=str(save.outcome),
            event_count=detection.event_count,
            window_start=detection.window_start.isoformat(),
            window_end=detection.window_end.isoformat(),
            latency_seconds=round(latency, 3),
            correlation_id=save.correlation_id,
        )

    result.duration_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "correlation_cycle",
        events_scanned=result.events_scanned,
        rules_evaluated=result.rules_evaluated,
        detections=result.detections_found,
        new=result.new_correlations,
        hits=result.hits,
        skipped_missing_group=result.skipped_missing_group,
        duration_ms=result.duration_ms,
    )
    return result


__all__ = ["CorrelationCycleResult", "run_correlation_cycle"]
