"""Mock Wazuh kaynak testleri (Faz 02): deterministik fixture davranışı."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.services.wazuh.errors import WazuhRateLimitedError, WazuhUnavailableError
from app.services.wazuh.mock_source import MockWazuhAlertSource
from app.services.wazuh.models import AlertQuery


async def test_list_alerts_returns_synthetic_fixture_sorted_desc() -> None:
    source = MockWazuhAlertSource()
    page = await source.list_alerts(AlertQuery())
    assert page.total == 6
    assert page.limit == 100
    timestamps = [a.timestamp for a in page.items]
    assert timestamps == sorted(timestamps, reverse=True)
    newest = page.items[0]
    assert newest.alert_id == "1792974900.123456"
    assert newest.rule_id == "5712"
    assert newest.rule_level == 10  # ORİJİNAL severity korunur


async def test_list_alerts_time_window_filter() -> None:
    source = MockWazuhAlertSource()
    since = datetime(2026, 10, 26, 8, 0, tzinfo=UTC)
    page = await source.list_alerts(AlertQuery(since=since))
    assert page.total == 3
    assert all(a.timestamp >= since for a in page.items)


async def test_list_alerts_pagination() -> None:
    source = MockWazuhAlertSource()
    page1 = await source.list_alerts(AlertQuery(offset=0, limit=2))
    page2 = await source.list_alerts(AlertQuery(offset=2, limit=2))
    page3 = await source.list_alerts(AlertQuery(offset=4, limit=2))
    assert page1.has_more and page2.has_more
    assert not page3.has_more
    ids1 = {a.alert_id for a in page1.items}
    ids2 = {a.alert_id for a in page2.items}
    ids3 = {a.alert_id for a in page3.items}
    assert len(ids1 | ids2 | ids3) == 6  # sayfalar örtüşmez, toplam 6


async def test_get_alert_found_and_missing() -> None:
    source = MockWazuhAlertSource()
    alert = await source.get_alert("1792972800.654321")
    assert alert is not None
    assert alert.rule_id == "550"
    assert alert.rule_level == 7
    assert alert.agent_name == "db-server-01"
    assert await source.get_alert("yok-boyle-id.000000") is None


async def test_error_queue_is_deterministic() -> None:
    source = MockWazuhAlertSource(
        error_queue=[
            WazuhRateLimitedError("429", retry_after_seconds=1.0),
            WazuhUnavailableError("5xx"),
        ]
    )
    with pytest.raises(WazuhRateLimitedError):
        await source.list_alerts(AlertQuery())
    with pytest.raises(WazuhUnavailableError):
        await source.list_alerts(AlertQuery())
    # kuyruk bitti → normal işlem
    page = await source.list_alerts(AlertQuery())
    assert page.total == 6


async def test_raw_field_preserves_original_payload() -> None:
    source = MockWazuhAlertSource()
    alert = await source.get_alert("1792969500.333444")
    assert alert is not None
    # izlenebilirlik: ham alert aynen taşınır (Faz 03'te saklanır)
    assert alert.raw["rule"]["id"] == "31151"
    assert alert.src_ip == "198.51.100.23"
