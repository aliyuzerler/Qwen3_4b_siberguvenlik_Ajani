"""Wazuh alert kaynağı sözleşmesi ve fabrika (Faz 02).

- WazuhAlertSource: tipli iç arayüz (phases/02-wazuh-integration.md).
- build_alert_source(): ayarlara göre mock veya indexer kaynağı üretir;
  yapılandırılmamışsa None döner (/ready "not_configured" raporlar).

Salt okunur sözleşme: arayüzde hiçbir yazma/metodasyon işlemi YOKTUR.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.core.config import Settings
from app.services.wazuh.models import AlertPage, AlertQuery, WazuhAlert


@runtime_checkable
class WazuhAlertSource(Protocol):
    """Alert okuma sözleşmesi — yalnızca salt okunur işlemler."""

    async def list_alerts(self, query: AlertQuery) -> AlertPage:
        """Zaman penceresi + sayfalama ile alert listesi."""
        ...

    async def get_alert(self, alert_id: str) -> WazuhAlert | None:
        """Tek alert detayı; yoksa None."""
        ...

    async def check_health(self) -> None:
        """Bağlantı kontrolü; hata durumunda WazuhError fırlatır."""
        ...

    async def aclose(self) -> None:
        """Kaynakları kapatır (HTTP istemcisi vb.)."""
        ...


def build_alert_source(settings: Settings) -> WazuhAlertSource | None:
    """Ayarlara uygun alert kaynağı üretir; yapılandırılmamışsa None döner."""
    # Lazy import: dairesel bağımlılık ve gereksiz istemci kurulumunu önler.
    from app.services.wazuh.indexer_source import WazuhIndexerSource
    from app.services.wazuh.mock_source import MockWazuhAlertSource

    if settings.wazuh_source_mode == "mock":
        return MockWazuhAlertSource()

    if not settings.wazuh_indexer_url:
        return None
    if not settings.wazuh_indexer_user or not settings.wazuh_indexer_password:
        return None

    return WazuhIndexerSource(
        base_url=settings.wazuh_indexer_url,
        user=settings.wazuh_indexer_user,
        password=settings.wazuh_indexer_password,
        index_pattern=settings.wazuh_index_pattern,
        timeout_seconds=settings.wazuh_timeout_seconds,
        verify_tls=settings.wazuh_verify_tls,
        max_retries=settings.wazuh_max_retries,
        backoff_base_seconds=settings.wazuh_backoff_base_seconds,
        breaker_failure_threshold=settings.wazuh_breaker_failure_threshold,
        breaker_reset_seconds=settings.wazuh_breaker_reset_seconds,
    )
