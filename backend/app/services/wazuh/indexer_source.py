"""Gerçek Wazuh Indexer alert kaynağı (Faz 02) — SALT OKUNUR.

Kanıt temelli tasarım (docs/phase-02-verification.md §"API kanıtı"):
- Wazuh Server API (55000) alert OKUMA sağlamaz; resmi spec'te yalnızca
  POST /events (ingest — KULLANILMAZ, yazma) vardır.
- Alert'ler Wazuh Indexer API'den (9200, OpenSearch) `wazuh-alerts-*`
  indeksinden okunur; en az yetkili erişim = indeks üzerinde yalnızca "read".

Salt okunur kanıtı (testlerle doğrulanır):
- Yalnızca GET / (health) ve POST {index}/_search çağrılır.
  OpenSearch'te _search gövdeli POST ile de OKUMA'dır; indeks mutasyonu yapmaz.
- DELETE/PUT/PATCH yok; config değişikliği endpoint'i yok.

Dayanıklılık: timeout, sınırlı retry (429 Retry-After'a saygılı), circuit breaker.
Gizlilik: credential yalnızca httpx auth param'ında; hata mesajı/loglara yazılmaz.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.core.logging import get_logger
from app.services.wazuh.errors import (
    WazuhAuthError,
    WazuhBadPayloadError,
    WazuhError,
    WazuhRateLimitedError,
    WazuhUnavailableError,
)
from app.services.wazuh.models import AlertPage, AlertQuery, WazuhAlert
from app.services.wazuh.parsing import parse_alert_hit
from app.services.wazuh.resilience import (
    AsyncSleep,
    CircuitBreaker,
    run_with_retry,
)

# Retry-After tavanı resilience.py'de uygulanır (MAX_RETRY_AFTER_SECONDS).

logger = get_logger(__name__)


class WazuhIndexerSource:
    """OpenSearch _search tabanlı salt okunur Wazuh alert kaynağı."""

    def __init__(
        self,
        *,
        base_url: str,
        user: str,
        password: str,
        index_pattern: str = "wazuh-alerts-*",
        timeout_seconds: float = 10.0,
        verify_tls: bool = True,
        max_retries: int = 2,
        backoff_base_seconds: float = 0.5,
        breaker_failure_threshold: int = 5,
        breaker_reset_seconds: float = 30.0,
        breaker: CircuitBreaker | None = None,
        sleep: AsyncSleep | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._index_pattern = index_pattern
        self._max_retries = max_retries
        self._backoff_base_seconds = backoff_base_seconds
        self._sleep = sleep
        # Testler hazır kesici enjekte edebilir; yoksa ayarlardan kurulur.
        self._breaker = breaker or CircuitBreaker(
            breaker_failure_threshold, breaker_reset_seconds
        )
        # Credential yalnızca auth param'da; URL/header'a asla gömülmez.
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            auth=(user, password),
            verify=verify_tls,
            timeout=httpx.Timeout(timeout_seconds),
            transport=transport,
        )

    # --- WazuhAlertSource sözleşmesi --------------------------------------
    async def list_alerts(self, query: AlertQuery) -> AlertPage:
        payload = await self._search(self._build_list_body(query))
        hits_node = self._expect_dict(payload.get("hits"), "'hits' nesnesi")
        hits = hits_node.get("hits")
        if not isinstance(hits, list):
            raise WazuhBadPayloadError("Wazuh yanıtı 'hits.hits' listesi içermiyor.")

        total: int | None = None
        total_node = hits_node.get("total")
        if isinstance(total_node, dict) and isinstance(total_node.get("value"), int):
            total = total_node["value"]

        items = [parse_alert_hit(hit) for hit in hits]
        return AlertPage(items=items, total=total, offset=query.offset, limit=query.limit)

    async def get_alert(self, alert_id: str) -> WazuhAlert | None:
        body = {
            "size": 1,
            "query": {"bool": {"filter": [{"match": {"id": alert_id}}]}},
        }
        payload = await self._search(body)
        hits_node = self._expect_dict(payload.get("hits"), "'hits' nesnesi")
        hits = hits_node.get("hits")
        if not isinstance(hits, list):
            raise WazuhBadPayloadError("Wazuh yanıtı 'hits.hits' listesi içermiyor.")
        if not hits:
            return None
        return parse_alert_hit(hits[0])

    async def check_health(self) -> None:
        """Bağlantı kontrolü: OpenSearch kök uç noktası (salt okunur, 200 bekler)."""
        await self._request("GET", "/")

    async def aclose(self) -> None:
        await self._client.aclose()

    # --- iç: sorgu gövdeleri ----------------------------------------------
    def _build_list_body(self, query: AlertQuery) -> dict[str, Any]:
        filters: list[dict[str, Any]] = []
        window: dict[str, Any] = {}
        if query.since is not None:
            window["gte"] = query.since.isoformat()
        if query.until is not None:
            window["lte"] = query.until.isoformat()
        if window:
            filters.append({"range": {"timestamp": window}})
        return {
            "from": query.offset,
            "size": query.limit,
            "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
            "sort": [
                {"timestamp": {"order": "desc"}},
                {"id": {"order": "desc"}},
            ],
            "track_total_hits": True,
        }

    # --- iç: HTTP katmanı ---------------------------------------------------
    async def _search(self, body: dict[str, Any]) -> dict[str, Any]:
        response = await self._request("POST", f"/{self._index_pattern}/_search", json=body)
        return self._decode_json(response)

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Breaker + retry sarmalayıcısı; her hata türü tipli karşılığına eşlenir."""
        await self._breaker.before_call()
        try:
            response = await run_with_retry(
                lambda: self._do_request(method, path, **kwargs),
                max_retries=self._max_retries,
                backoff_base_seconds=self._backoff_base_seconds,
                sleep=self._sleep,
            )
        except WazuhError:
            await self._breaker.record_failure()
            raise
        await self._breaker.record_success()
        # Loglama: yalnızca method + path + status; body/header ASLA loglanmaz
        # (full_log hassas veri içerebilir; AGENTS.md §6, wazuh skill §10).
        logger.info("wazuh_request", method=method, path=path, status=response.status_code)
        return response

    async def _do_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = await self._client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise WazuhUnavailableError(
                f"Wazuh Indexer zaman aşımı ({path})."
            ) from exc
        except httpx.TransportError as exc:
            raise WazuhUnavailableError(
                f"Wazuh Indexer'a bağlanılamadı ({type(exc).__name__})."
            ) from exc

        status = response.status_code
        if status == 200:
            return response
        if status in (401, 403):
            raise WazuhAuthError(
                f"Wazuh Indexer yetki hatası (HTTP {status}): servis hesabı salt "
                "okunur izinlere sahip mi? Kullanıcı/parola doğrulayın."
            )
        if status == 429:
            retry_after = self._parse_retry_after(response.headers.get("Retry-After"))
            detail = f" (Retry-After: {retry_after:g}s)" if retry_after is not None else ""
            raise WazuhRateLimitedError(
                f"Wazuh Indexer oran sınırı (HTTP 429){detail}.", retry_after
            )
        if status >= 500:
            raise WazuhUnavailableError(f"Wazuh Indexer sunucu hatası (HTTP {status}).")
        raise WazuhBadPayloadError(
            f"Wazuh Indexer beklenmeyen HTTP durumu: {status} ({path})."
        )

    @staticmethod
    def _parse_retry_after(value: str | None) -> float | None:
        """Retry-After (saniye biçimi) → float; çözümlenemezse None."""
        if value is None:
            return None
        try:
            return max(0.0, float(value.strip()))
        except ValueError:
            return None

    def _decode_json(self, response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:  # json.JSONDecodeError ⊂ ValueError
            raise WazuhBadPayloadError(
                "Wazuh Indexer yanıtı geçerli JSON değil (bozuk gövde)."
            ) from exc
        return self._expect_dict(payload, "yanıt kökü")

    @staticmethod
    def _expect_dict(value: Any, label: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise WazuhBadPayloadError(f"Wazuh Indexer {label} sözlük değil; şema bozuk.")
        return value
