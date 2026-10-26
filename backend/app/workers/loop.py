"""Birleşik arka plan worker döngüsü: fetch → store → analyze (Faz 04).

Faz 03 notunun tamamlanması: "Zamanlanmış arka plan döngüsü Faz 04'te
analysis worker ile birlikte etkinleştirilecektir (tek döngü: fetch →
store → analyze)."

Davranış:
- Varsayılan KAPALI (WORKER_LOOP_ENABLED=false): güvenli başlangıç —
  döngü ancak operatör açar. Açık olduğunda her WORKER_INTERVAL_SECONDS
  aralıkta:
    1. Wazuh kaynağı yapılandırılmışsa ingest döngüsü (Faz 03) — kaynağı
       olmayan kurulumda adım sessizce atlanır (/ready "not_configured").
    2. Analysis döngüsü (Faz 04) — ANALYSIS_ENABLED=false ise atlanır.
- Ingest zaman penceresi: ilk turda WORKER_INITIAL_WINDOW_SECONDS geriye;
  sonrasında son başarılı turdaki en büyük event timestamp'inden itibaren
  (cursor). Kaynak boşsa cursor korunur. Başarısız turda cursor İLERLEMEZ
  (idempotent saklama sayesinde aynı pencere güvenle yeniden çekilir).
- Tek tur içindeki hatalar izole edilir: ingest hatası analiz adımını
  ENGELLEMEZ; analiz altyapı hatası döngüyü değil yalnızca o turu bitirir.
- Cancellation: stop_event set edilince mevcut tur bitince çıkar; kapanışta
  create_app task.cancel + join yapar (lifespan).
- Tek yazar varsayımı: döngü tek asyncio task'tır; birden fazla backend
  replika kopyası bu fazda desteklenmez (belgelenmiş kısıt; Faz 08).
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.logging import get_logger
from app.services.analysis.analyzer import EventAnalyzer
from app.services.analysis.errors import AnalysisError
from app.services.analysis.metrics import AnalysisMetrics
from app.services.normalization.errors import StorageError
from app.services.normalization.redaction import RedactionPolicy
from app.services.normalization.repository import EventRepository
from app.services.wazuh.models import AlertQuery
from app.services.wazuh.source import WazuhAlertSource
from app.workers.analysis import run_analysis_cycle
from app.workers.ingest import run_ingest_cycle

logger = get_logger(__name__)


@dataclass
class WorkerLoopStats:
    """Döngü ömrü boyunca kümülatif sayaçlar (izlenebilirlik)."""

    iterations: int = 0
    ingest_cycles: int = 0
    analysis_cycles: int = 0
    last_cursor: datetime | None = None
    errors: list[str] = field(default_factory=list)


async def run_worker_loop(
    sessionmaker: async_sessionmaker[AsyncSession],
    analyzer: EventAnalyzer,
    *,
    stop_event: asyncio.Event,
    interval_seconds: float,
    batch_size: int,
    metrics: AnalysisMetrics,
    source: WazuhAlertSource | None = None,
    policy: RedactionPolicy | None = None,
    store_raw: bool = False,
    initial_window_seconds: float = 900.0,
    ingest_max_pages: int = 5,
    stats: WorkerLoopStats | None = None,
) -> None:
    """Sonsuz döngü: her aralıkta ingest + analiz; stop_event ile çıkar."""
    if policy is None:
        policy = RedactionPolicy()
    state = stats or WorkerLoopStats()
    cursor = datetime.now(UTC) - timedelta(seconds=initial_window_seconds)

    while not stop_event.is_set():
        state.iterations += 1
        try:
            cursor = await _run_once(
                sessionmaker,
                analyzer,
                cursor=cursor,
                source=source,
                policy=policy,
                store_raw=store_raw,
                batch_size=batch_size,
                metrics=metrics,
                ingest_max_pages=ingest_max_pages,
                state=state,
            )
        except (AnalysisError, StorageError) as exc:
            # Altyapı hatası: tur başarısız; cursor korunur (yeniden deneme
            # idempotent). Döngü ÇÖKMEZ — sonraki aralıkta tekrar denenir.
            state.errors.append(exc.message)
            logger.warning("worker_cycle_failed", error=exc.message, cursor=cursor.isoformat())
        except Exception as exc:  # noqa: BLE001 — döngü her şeye rağmen yaşamalı
            state.errors.append(f"beklenmeyen: {type(exc).__name__}")
            logger.exception("worker_cycle_unexpected_error")

        state.last_cursor = cursor
        # Aralık bekleme: stop_event set edilirse derhal çıkar; süre dolarsa yeni tur.
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
    logger.info("worker_loop_stopped", iterations=state.iterations)


async def _run_once(
    sessionmaker: async_sessionmaker[AsyncSession],
    analyzer: EventAnalyzer,
    *,
    cursor: datetime,
    source: WazuhAlertSource | None,
    policy: RedactionPolicy,
    store_raw: bool,
    batch_size: int,
    metrics: AnalysisMetrics,
    ingest_max_pages: int,
    state: WorkerLoopStats,
) -> datetime:
    """Tek tur: ingest (opsiyonel) + analiz; yeni cursor döner."""
    # --- 1) Ingest (kaynak yapılandırılmışsa) ---
    if source is not None:
        query = AlertQuery(since=cursor, limit=100)
        ingest_result = await run_ingest_cycle(
            source,
            EventRepository(sessionmaker),
            policy,
            query=query,
            store_raw=store_raw,
            max_pages=ingest_max_pages,
        )
        state.ingest_cycles += 1
        logger.info(
            "worker_ingest_cycle",
            pages=ingest_result.pages,
            fetched=ingest_result.fetched,
            stored=ingest_result.stored,
            duplicate=ingest_result.duplicate,
            variant=ingest_result.variant,
            failed=ingest_result.failed,
        )
        # Cursor: yalnızca tur hatasız bittiğinde ilerler. Son event zamanı
        # (maks) + 1µs: aynı timestamp'li yeni alert'ler kaçmasın.
        latest = ingest_result.latest_event_at
        if latest is not None:
            cursor = latest + timedelta(microseconds=1)

    # --- 2) Analiz (pending event'ler) ---
    analysis_result = await run_analysis_cycle(
        sessionmaker, analyzer, batch_size=batch_size, metrics=metrics
    )
    state.analysis_cycles += 1
    logger.info(
        "worker_analysis_cycle",
        pending=analysis_result.pending_seen,
        completed=analysis_result.completed,
        failed=analysis_result.failed,
        skipped=analysis_result.skipped,
    )
    snapshot = metrics.snapshot()
    logger.info(
        "worker_analysis_metrics",
        total=snapshot.total,
        schema_valid_rate=round(snapshot.schema_valid_rate, 4),
        p50_ms=snapshot.p50_ms,
        p95_ms=snapshot.p95_ms,
        error_rate=round(snapshot.error_rate, 4),
    )
    return cursor


__all__ = ["WorkerLoopStats", "run_worker_loop"]
