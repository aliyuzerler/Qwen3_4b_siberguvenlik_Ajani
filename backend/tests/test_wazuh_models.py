"""Wazuh iç model testleri (Faz 02): DTO, severity, zaman normalizasyonu."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.services.wazuh.models import (
    AlertPage,
    AlertQuery,
    WazuhAlert,
    normalize_timestamp,
    severity_label,
)


def test_severity_label_coarse_mapping() -> None:
    assert severity_label(0) == "yoksayildi"
    assert severity_label(3) == "dusuk"
    assert severity_label(4) == "orta"
    assert severity_label(6) == "orta"
    assert severity_label(7) == "yuksek"
    assert severity_label(15) == "yuksek"


def test_normalize_timestamp_naive_becomes_utc() -> None:
    naive = datetime(2026, 10, 26, 9, 0, 0)
    normalized = normalize_timestamp(naive)
    assert normalized.tzinfo is UTC
    assert normalized.hour == 9  # UTC varsayımı: saat değişmez


def test_normalize_timestamp_converts_to_utc() -> None:
    tr_tz = timezone(timedelta(hours=3))
    local = datetime(2026, 10, 26, 12, 0, 0, tzinfo=tr_tz)
    normalized = normalize_timestamp(local)
    assert normalized.tzinfo is UTC
    assert normalized.hour == 9


def _alert(**overrides: object) -> WazuhAlert:
    values: dict[str, object] = {
        "alert_id": "1792974900.123456",
        "timestamp": datetime(2026, 10, 26, 9, 15, tzinfo=UTC),
        "rule_id": "5712",
        "rule_level": 10,
        "rule_description": "sshd: Brute force trying to get access to the system.",
        "rule_groups": ["syslog", "sshd"],
    }
    values.update(overrides)
    return WazuhAlert(**values)  # type: ignore[arg-type]


def test_alert_preserves_original_severity_int() -> None:
    alert = _alert()
    # Kanonik severity int'tir; etiket yalnızca kaba UI ipucudur.
    assert alert.rule_level == 10
    assert alert.severity == "yuksek"


def test_alert_rejects_out_of_range_level() -> None:
    with pytest.raises(ValidationError):
        _alert(rule_level=16)
    with pytest.raises(ValidationError):
        _alert(rule_level=-1)


def test_alert_query_bounds_and_window_normalization() -> None:
    query = AlertQuery(since=datetime(2026, 10, 26, 12, 0, tzinfo=timezone(timedelta(hours=3))))
    assert query.since is not None and query.since.hour == 9 and query.since.tzinfo is UTC
    with pytest.raises(ValidationError):
        AlertQuery(limit=0)
    with pytest.raises(ValidationError):
        AlertQuery(limit=1001)
    with pytest.raises(ValidationError):
        AlertQuery(offset=-1)


def test_alert_page_has_more() -> None:
    page_full = AlertPage(items=[_alert()] * 2, total=5, offset=0, limit=2)
    assert page_full.has_more is True
    page_last = AlertPage(items=[_alert()] * 2, total=4, offset=2, limit=2)
    assert page_last.has_more is False
    # total bilinmiyorsa dolu sayfa "devam var" sayılır (temkinli davranış)
    page_unknown = AlertPage(items=[_alert()] * 2, total=None, offset=0, limit=2)
    assert page_unknown.has_more is True
