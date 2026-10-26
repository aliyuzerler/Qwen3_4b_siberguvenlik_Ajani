"""Alert alma döngüsü: fetch → normalize → idempotent saklama (Faz 03).

Bu modül, Faz 02'nin salt-okunur alert kaynağını Faz 03'ün deposuna bağlar.
Zamanlanmış arka plan döngüsü Faz 04'te analysis worker ile birlikte
etkinleştirilecektir (tek döngü: fetch → store → analyze); bu fazda döngü
fonksiyonu test edilebilir ve yeniden kullanılabilir olarak sunulur.

Kurallar:
- Kaynak erişimi salt okunurdur (WazuhAlertSource sözleşmesi, Faz 02).
- Bozuk tek alert batch'i bloklamaz: NormalizationError izole edilir,
  sayaçlanır (failed) ve döngü devam eder (AGENTS.md §7: negatif yollar).
- DB altyapı hatası (retryable StorageError) fail-fast yükseltilir:
  çağıran worker aynı sayfayı idempotency sayesinde güvenle tekrar alabilir.
- Ham alert, yalnızca store_raw=True ise depoya yazılır (varsayılan kapalı;
  gerekçe: docs/phase-03-verification.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.services.normalization.errors import NormalizationError
from app.services.normalization.models import NormalizedEvent
from app.services.normalization.normalizer import normalize_alert
from app.services.normalization.redaction import RedactionPolicy
from app.services.normalization.repository import EventRepository, StoreFailure
from app.services.wazuh.models import AlertPage, AlertQuery
from app.services.wazuh.source import WazuhAlertSource

# Tek döngüde en fazla kaç sayfa çekilir (güvenlik tavanı; sonsuz sayfa yok).
MAX_PAGES_PER_CYCLE = 5


@dataclass
class IngestCycleResult:
    """Tek alma döngüsünün ölçülebilir sonucu (başarı ölçütü, AGENTS.md §7)."""

    pages: int = 0
    fetched: int = 0
    normalized: int = 0
    failed: int = 0
    stored: int = 0
    duplicate: int = 0
    variant: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total_ok(self) -> int:
        return self.stored + self.duplicate + self.variant


def _normalize_page(
    page: AlertPage, policy: RedactionPolicy, result: IngestCycleResult
) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for alert in page.items:
        try:
            events.append(normalize_alert(alert, policy))
        except NormalizationError as exc:
            result.failed += 1
            result.errors.append(f"normalizasyon: alert bozuk ({exc.message})")
    return events


async def run_ingest_cycle(
    source: WazuhAlertSource,
    repository: EventRepository,
    policy: RedactionPolicy,
    *,
    query: AlertQuery,
    store_raw: bool = False,
    max_pages: int = MAX_PAGES_PER_CYCLE,
) -> IngestCycleResult:
    """Alert sayfalarını çeker, normalleştirir ve idempotent saklar.

    Depolama, event başına transaction kullanır: batch içinde tek bozuk
    event diğerlerinin saklanmasını engellemez; retryable DB hatasında
    ise döngü derhal kesilir (kısmi batch güvenle tekrar edilebilir).
    """
    result = IngestCycleResult()
    offset = query.offset

    for _ in range(max_pages):
        page_query = query.model_copy(update={"offset": offset})
        page = await source.list_alerts(page_query)
        result.pages += 1
        result.fetched += len(page.items)

        events = _normalize_page(page, policy, result)
        result.normalized += len(events)

        if events:
            raws: dict[str, dict[str, object]] | None = None
            if store_raw:
                raw_by_id = {alert.alert_id: alert.raw for alert in page.items}
                raws = {
                    event.alert_id: raw_by_id[event.alert_id]
                    for event in events
                    if event.alert_id in raw_by_id
                }
            ingest = await repository.store_batch(events, raws=raws)
            result.stored += ingest.stored
            result.duplicate += ingest.duplicate
            result.variant += ingest.variant
            result.failed += ingest.failed
            result.errors.extend(
                f"depolama: {f.alert_id} ({f.message})" for f in ingest.failures
            )

        if not page.has_more or not page.items:
            break
        offset += len(page.items)

    return result


__all__ = ["IngestCycleResult", "MAX_PAGES_PER_CYCLE", "run_ingest_cycle", "StoreFailure"]
