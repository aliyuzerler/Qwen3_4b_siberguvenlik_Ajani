"""Mock Wazuh alert kaynağı (mock-first geliştirme, Faz 02).

- Gerçek Wazuh'a erişim olmadan panel/geliştirme/bağımsız test sağlar.
- Sentetik fixture'dan beslenir (fixtures/sample_alerts.json).
- Gerçek indexer istemcisiyle AYNI parse yolunu kullanır (parsing.py).
- Hata enjeksiyonu destekler: kuyruktaki hatalar sırayla fırlatılır;
  kuyruk bitince çağrılar başarılı olur (deterministik negatif testler).

Güvenlik: mock mod üretimde yasaktır (config validator, AGENTS.md §3).
"""

from __future__ import annotations

import json
from datetime import datetime
from importlib import resources
from typing import Any

from app.services.wazuh.errors import WazuhBadPayloadError, WazuhError
from app.services.wazuh.models import AlertPage, AlertQuery, WazuhAlert
from app.services.wazuh.parsing import parse_alert_hit

FIXTURE_NAME = "sample_alerts.json"


def load_fixture_hits() -> list[dict[str, Any]]:
    """Paket içi sentetik fixture'ı OpenSearch hit biçimine sararak döndürür."""
    raw = resources.files("app.services.wazuh.fixtures").joinpath(FIXTURE_NAME).read_text(
        encoding="utf-8"
    )
    data = json.loads(raw)
    alerts = data.get("alerts")
    if not isinstance(alerts, list) or not alerts:
        raise WazuhBadPayloadError("Sentetik fixture boş veya hatalı.")
    return [{"_id": str(a.get("id")), "_source": a} for a in alerts]


class MockWazuhAlertSource:
    """Fixture tabanlı deterministik alert kaynağı (WazuhAlertSource sözleşmesi)."""

    def __init__(
        self,
        *,
        hits: list[dict[str, Any]] | None = None,
        error_queue: list[WazuhError] | None = None,
    ) -> None:
        self._hits = hits if hits is not None else load_fixture_hits()
        self._error_queue = list(error_queue or [])
        self._closed = False

    # --- hata enjeksiyonu -------------------------------------------------
    def _pop_error(self) -> WazuhError | None:
        if self._error_queue:
            return self._error_queue.pop(0)
        return None

    # --- WazuhAlertSource sözleşmesi --------------------------------------
    async def list_alerts(self, query: AlertQuery) -> AlertPage:
        if (error := self._pop_error()) is not None:
            raise error

        items: list[tuple[datetime, str, WazuhAlert]] = []
        for hit in self._hits:
            alert = parse_alert_hit(hit)
            if query.since is not None and alert.timestamp < query.since:
                continue
            if query.until is not None and alert.timestamp > query.until:
                continue
            items.append((alert.timestamp, alert.alert_id, alert))

        # Deterministik sıra: timestamp desc, sonra alert_id desc
        items.sort(key=lambda entry: (entry[0], entry[1]), reverse=True)
        window = items[query.offset : query.offset + query.limit]
        return AlertPage(
            items=[alert for _, _, alert in window],
            total=len(items),
            offset=query.offset,
            limit=query.limit,
        )

    async def get_alert(self, alert_id: str) -> WazuhAlert | None:
        if (error := self._pop_error()) is not None:
            raise error
        for hit in self._hits:
            alert = parse_alert_hit(hit)
            if alert.alert_id == alert_id:
                return alert
        return None

    async def check_health(self) -> None:
        if (error := self._pop_error()) is not None:
            raise error

    async def aclose(self) -> None:
        self._closed = True
