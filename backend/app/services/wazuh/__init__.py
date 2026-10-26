"""Wazuh entegrasyon paketi (Faz 02) — salt okunur alert kaynağı."""

from __future__ import annotations

from app.services.wazuh.errors import (
    WazuhAuthError,
    WazuhBadPayloadError,
    WazuhError,
    WazuhNotConfiguredError,
    WazuhRateLimitedError,
    WazuhUnavailableError,
)
from app.services.wazuh.models import AlertPage, AlertQuery, WazuhAlert
from app.services.wazuh.source import WazuhAlertSource, build_alert_source
from app.services.wazuh.status import WazuhStatusSnapshot, WazuhStatusTracker

__all__ = [
    "AlertPage",
    "AlertQuery",
    "WazuhAlert",
    "WazuhAlertSource",
    "WazuhAuthError",
    "WazuhBadPayloadError",
    "WazuhError",
    "WazuhNotConfiguredError",
    "WazuhRateLimitedError",
    "WazuhStatusSnapshot",
    "WazuhStatusTracker",
    "WazuhUnavailableError",
    "build_alert_source",
]
