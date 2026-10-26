"""Wazuh Indexer sözleşme testleri (Faz 02) — TEST-PROMPT-TEMPLATE temelli.

Bağımsız faz test promptu gereği simüle edilen senaryolar:
başarılı yanıt, boş liste, sayfalama, 401/403, 429 (Retry-After), 5xx,
timeout, bozuk JSON, bağlantı kesintisi + salt-okunur kanıtı + sızıntı yokluğu.

Yöntem: GERÇEK WazuhIndexerSource + httpx.MockTransport (ağ yok).
Böylece gerçek kod yolu (istek kurma, hata eşleme, parse) doğrulanır.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from structlog.testing import capture_logs

from app.services.wazuh.errors import (
    WazuhAuthError,
    WazuhBadPayloadError,
    WazuhError,
    WazuhRateLimitedError,
    WazuhUnavailableError,
)
from app.services.wazuh.indexer_source import WazuhIndexerSource
from app.services.wazuh.mock_source import load_fixture_hits
from app.services.wazuh.models import AlertQuery
from app.services.wazuh.resilience import CircuitBreaker

TEST_USER = "ajant-readonly"
TEST_PASSWORD = "SAHTE-ORNEK-PAROLA-abc123"  # noqa: S105 — yalnızca test değeri
INDEX_PATTERN = "wazuh-alerts-*"

Hit = dict[str, Any]


class SleepNoop:
    """Retry beklemelerini anında geçer; beklemeler kayda geçer."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def make_source(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    max_retries: int = 0,
    breaker: CircuitBreaker | None = None,
) -> tuple[WazuhIndexerSource, SleepNoop]:
    sleep = SleepNoop()
    source = WazuhIndexerSource(
        base_url="https://indexer.test:9200",
        user=TEST_USER,
        password=TEST_PASSWORD,
        index_pattern=INDEX_PATTERN,
        verify_tls=True,
        max_retries=max_retries,
        backoff_base_seconds=0.01,
        breaker=breaker or CircuitBreaker(50, 30.0),
        sleep=sleep,
        transport=httpx.MockTransport(handler),
    )
    return source, sleep


def envelope(hits: list[Hit], total: int) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "took": 3,
            "hits": {
                "total": {"value": total},
                "hits": [
                    {
                        "_index": "wazuh-alerts-4.x-2026.10.26",
                        "_id": h["_id"],
                        "_source": h["_source"],
                    }
                    for h in hits
                ],
            },
        },
    )


# --- 1) Başarılı yanıt + alan koruması -----------------------------------


async def test_list_alerts_success_maps_fields() -> None:
    hits = load_fixture_hits()
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return envelope(hits, total=len(hits))

    source, _ = make_source(handler)
    page = await source.list_alerts(AlertQuery(limit=10))

    assert page.total == len(hits)
    assert len(page.items) == 6
    newest = page.items[0]
    # Alert ID, timestamp, rule ve ORİJİNAL severity kaybolmaz (faz gereksinimi)
    assert newest.alert_id == "1792974900.123456"
    assert newest.rule_id == "5712"
    assert newest.rule_level == 10
    assert newest.rule_description.startswith("sshd: Brute force")
    assert newest.timestamp.year == 2026 and newest.timestamp.tzinfo is not None
    assert newest.agent_name == "web-server-01"

    # Kimlik doğrulama: Basic auth başlığı uygulandı
    auth_header = seen[0].headers["Authorization"]
    assert auth_header.startswith("Basic ")
    decoded = base64.b64decode(auth_header.removeprefix("Basic ")).decode()
    assert decoded == f"{TEST_USER}:{TEST_PASSWORD}"
    # Parola URL'e asla gömülmez
    assert TEST_PASSWORD not in str(seen[0].url)


async def test_get_alert_by_id_and_empty_result() -> None:
    hits = load_fixture_hits()
    target = hits[1]
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        wanted = body["query"]["bool"]["filter"][0]["match"]["id"]
        matched = [h for h in hits if h["_source"]["id"] == wanted]
        return envelope(matched, total=len(matched))

    source, _ = make_source(handler)
    alert = await source.get_alert(str(target["_source"]["id"]))
    assert alert is not None
    assert alert.alert_id == str(target["_source"]["id"])
    assert alert.rule_level == target["_source"]["rule"]["level"]

    assert await source.get_alert("bilmem-ne.000001") is None


# --- 2) Boş liste ve sayfalama -------------------------------------------


async def test_list_alerts_empty_index() -> None:
    source, _ = make_source(lambda request: envelope([], total=0))
    page = await source.list_alerts(AlertQuery())
    assert page.items == []
    assert page.total == 0
    assert page.has_more is False


async def test_list_alerts_pagination_uses_from_size() -> None:
    hits = load_fixture_hits()
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        offset, size = int(body.get("from", 0)), int(body.get("size", 10))
        return envelope(hits[offset : offset + size], total=len(hits))

    source, _ = make_source(handler)
    page1 = await source.list_alerts(AlertQuery(offset=0, limit=4))
    page2 = await source.list_alerts(AlertQuery(offset=4, limit=4))

    assert [a.alert_id for a in page1.items] != [a.alert_id for a in page2.items]
    assert page1.has_more is True
    assert page2.has_more is False
    body1 = json.loads(seen[0].content)
    body2 = json.loads(seen[1].content)
    assert (body1["from"], body1["size"]) == (0, 4)
    assert (body2["from"], body2["size"]) == (4, 4)
    # timestamp desc sıralama isteği karşılanır
    assert body1["sort"] == [{"timestamp": {"order": "desc"}}, {"id": {"order": "desc"}}]


# --- 3) Hata durumları ----------------------------------------------------


async def test_401_maps_to_auth_error_without_retry() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(401, json={"error": "unauthorized"})

    source, sleep = make_source(handler)
    with pytest.raises(WazuhAuthError) as exc:
        await source.list_alerts(AlertQuery())
    assert calls == [1]  # tek deneme: 401 tekrarlanmaz
    assert sleep.delays == []
    assert TEST_PASSWORD not in str(exc.value)


async def test_403_maps_to_auth_error() -> None:
    source, _ = make_source(lambda request: httpx.Response(403, json={"error": "forbidden"}))
    with pytest.raises(WazuhAuthError):
        await source.check_health()


async def test_429_retries_with_retry_after_then_succeeds() -> None:
    hits = load_fixture_hits()
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, json={"error": "rate"}, headers={"Retry-After": "2"})
        return envelope(hits, total=len(hits))

    source, sleep = make_source(handler, max_retries=2)
    page = await source.list_alerts(AlertQuery())
    assert page.total == len(hits)
    assert len(calls) == 2  # ilk istek 429 → tek retry
    # Retry-After'a saygı: beklenen uyu, üstel backoff değil
    assert sleep.delays == [2.0]


async def test_429_exhausts_retries_then_raises() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(429, json={"error": "rate"}, headers={"Retry-After": "1"})

    source, _ = make_source(handler, max_retries=1)
    with pytest.raises(WazuhRateLimitedError):
        await source.list_alerts(AlertQuery())
    assert len(calls) == 2  # ilk + 1 retry


async def test_5xx_retries_then_raises_unavailable() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(503, json={"error": "unavailable"})

    source, sleep = make_source(handler, max_retries=1)
    with pytest.raises(WazuhUnavailableError):
        await source.list_alerts(AlertQuery())
    assert len(calls) == 2
    assert len(sleep.delays) == 1  # araya backoff girdi


async def test_timeout_maps_to_unavailable() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectTimeout("bağlantı zaman aşımı")

    source, _ = make_source(handler, max_retries=1)
    with pytest.raises(WazuhUnavailableError):
        await source.list_alerts(AlertQuery())
    assert len(calls) == 2


async def test_connection_error_maps_to_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("bağlantı reddedildi")

    source, _ = make_source(handler, max_retries=1)
    with pytest.raises(WazuhUnavailableError) as exc:
        await source.check_health()
    assert TEST_PASSWORD not in str(exc.value)


async def test_broken_json_maps_to_bad_payload_without_retry() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200, content=b'{"hits": {kesik...')

    source, sleep = make_source(handler)
    with pytest.raises(WazuhBadPayloadError):
        await source.list_alerts(AlertQuery())
    assert calls == [1]  # bozuk gövde tekrar denenmez
    assert sleep.delays == []


async def test_malformed_hit_missing_rule_level_rejected() -> None:
    bad_hit = {"_id": "x", "_source": {"id": "x.1", "timestamp": "2026-10-26T09:00:00.000+0000"}}

    def handler(request: httpx.Request) -> httpx.Response:
        return envelope([bad_hit], total=1)

    source, _ = make_source(handler)
    with pytest.raises(WazuhBadPayloadError) as exc:
        await source.list_alerts(AlertQuery())
    assert "rule.level" in str(exc.value)


# --- 4) Salt-okunur kanıtı ------------------------------------------------


async def test_source_issues_only_read_requests() -> None:
    """Salt-okunur kanıtı: yalnızca GET / ve POST _search; yazma yok (faz kuralı)."""
    hits = load_fixture_hits()
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/":
            return httpx.Response(200, json={"cluster_name": "wazuh", "version": {"number": "4.x"}})
        body = json.loads(request.content)
        offset, size = int(body.get("from", 0)), int(body.get("size", 10))
        return envelope(hits[offset : offset + size], total=len(hits))

    source, _ = make_source(handler)
    await source.check_health()
    await source.list_alerts(AlertQuery(offset=0, limit=2))
    await source.get_alert("1792974900.123456")
    await source.aclose()

    allowed_paths = {"/", f"/{INDEX_PATTERN}/_search"}
    for request in seen:
        assert request.method in ("GET", "POST"), f"yazma metodu görüldü: {request.method}"
        assert request.url.path in allowed_paths, f"yabancı path: {request.url.path}"
    methods = {r.method for r in seen}
    assert "DELETE" not in methods and "PUT" not in methods


# --- 5) Sızıntı yokluğu: credential loglarda/mesajlarda değil --------------


async def test_adapter_logs_contain_no_credentials() -> None:
    """İstek logları method/path/status içerir; user/parola asla (AGENTS.md §6)."""
    hits = load_fixture_hits()
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] <= 1:
            return httpx.Response(503, json={"error": "x"})
        return envelope(hits, total=len(hits))

    source, _ = make_source(handler, max_retries=2)
    with capture_logs() as events:
        page = await source.list_alerts(AlertQuery())
        assert page.total == len(hits)

    request_logs = [e for e in events if e.get("event") == "wazuh_request"]
    assert request_logs, "adapter en az bir istek loglamalıydı"
    dumped = json.dumps(events, ensure_ascii=False, default=str)
    assert TEST_PASSWORD not in dumped
    assert TEST_USER not in dumped
    # yararlı içerik: method/path/status var
    assert any("_search" in str(e.get("path")) for e in request_logs)
    assert all("authorization" not in json.dumps(e).lower() for e in request_logs)


async def test_error_messages_do_not_contain_credentials() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    source, _ = make_source(handler)
    with pytest.raises(WazuhError) as exc:
        await source.list_alerts(AlertQuery())
    message = str(exc.value) + " ".join(str(a) for a in exc.value.args)
    assert TEST_PASSWORD not in message
    assert TEST_USER not in message


# --- 6) Devre kesici davranışı --------------------------------------------


async def test_circuit_breaker_stops_hammering_a_dead_indexer() -> None:
    calls: list[int] = []
    breaker = CircuitBreaker(failure_threshold=2, reset_seconds=30.0)

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(503, json={"error": "down"})

    source, _ = make_source(handler, max_retries=0, breaker=breaker)
    for _ in range(2):
        with pytest.raises(WazuhUnavailableError):
            await source.check_health()
    # eşik doldu → kesici açık; yeni çağrılar handler'a HİÇ gitmez
    dead_calls = len(calls)
    with pytest.raises(WazuhUnavailableError) as exc:
        await source.check_health()
    assert len(calls) == dead_calls
    assert "devre kesici" in str(exc.value)
    assert breaker.state == CircuitBreaker.OPEN
