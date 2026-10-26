"""Wazuh bağlantı durumu takibi (Faz 02).

"Bağlantı durumu ve son başarılı senkronizasyon bilgisi" gereksinimi
(phases/02-wazuh-integration.md): kalıcı saklama Faz 03'te DB'ye taşınır;
bu fazda süreç içi iz sürücü yeterlidir.

Durumlar: not_configured | up | down
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from app.services.wazuh.errors import WazuhError


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class WazuhStatusSnapshot:
    """Tek noktada okunabilir bağlantı durumu."""

    state: str
    last_successful_check: datetime | None
    last_error: str | None
    checked_at: datetime | None


class WazuhStatusTracker:
    """Wazuh kaynak kontrol sonuçlarını izler (süreç içi)."""

    def __init__(self, *, configured: bool) -> None:
        self._configured = configured
        self._last_successful_check: datetime | None = None
        self._last_error: str | None = None
        self._checked_at: datetime | None = None

    def record_success(self) -> None:
        self._last_successful_check = _utcnow()
        self._last_error = None
        self._checked_at = _utcnow()

    def record_failure(self, error: WazuhError | Exception) -> None:
        # Hata mesajı credential içermemeli (errors.py sözleşmesi)
        self._last_error = error.message if isinstance(error, WazuhError) else str(error)
        self._checked_at = _utcnow()

    @property
    def state(self) -> str:
        if not self._configured:
            return "not_configured"
        if self._last_successful_check is None:
            return "down" if self._last_error else "not_configured"
        return "up"

    def snapshot(self) -> WazuhStatusSnapshot:
        return WazuhStatusSnapshot(
            state=self.state,
            last_successful_check=self._last_successful_check,
            last_error=self._last_error,
            checked_at=self._checked_at,
        )
