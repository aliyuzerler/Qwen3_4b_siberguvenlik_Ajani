"""Liveness ve readiness endpoint'leri (Faz 01/02/04 kabul ölçütleri).

- GET /api/v1/health  (liveness): süreç ayakta mı? Bağımlılıklara bakmaz.
- GET /api/v1/ready   (readiness): DB + Wazuh + Ollama bağlantı durumu.
  Ollama bileşeni Faz 04'te eklendi: servis sağlık yoklaması + model
  kurulum kontrolü (GET /api/version, GET /api/tags — salt okunur).

Ollama bileşen durumları:
- disabled        → ANALYSIS_ENABLED=false (kill switch açık)
- not_configured  → istemci yok (beklenmedik; istemci her zaman kurulur)
- model_missing   → Ollama ayakta ama OLLAMA_MODEL_TAG kurulu değil
- down            → erişilemedi (bağlantı/zaman aşımı/5xx)
- up              → servis ayakta ve model kurulu

Ollama down/model_missing genel ready'yi 503 YAPMAZ (200 + bileşen durumu):
panel bileşen kartlarında gösterilir (Faz 05); analiz döngüsü kendi
dayanıklılığıyla bekler. Yalnızca DB down 503'tür.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.services.analysis.errors import (
    OllamaError,
    OllamaModelMissingError,
)
from app.services.wazuh.errors import WazuhError

router = APIRouter(tags=["health"])

DB_CHECK_TIMEOUT_SECONDS = 3.0
WAZUH_CHECK_TIMEOUT_SECONDS = 3.0
OLLAMA_CHECK_TIMEOUT_SECONDS = 3.0


@router.get("/health")
async def liveness() -> JSONResponse:
    """Liveness: süreç canlı mı? Harici bağımlılık kontrolü yapmaz."""
    return JSONResponse(status_code=200, content={"status": "ok"})


async def _wazuh_component(request: Request) -> str:
    """Wazuh alert kaynağını zaman aşımıyla yoklar; durum metni döner."""
    source = getattr(request.app.state, "wazuh_source", None)
    tracker = getattr(request.app.state, "wazuh_status", None)
    if source is None:
        return "not_configured"
    try:
        async with asyncio.timeout(WAZUH_CHECK_TIMEOUT_SECONDS):
            await source.check_health()
    except WazuhError as exc:
        if tracker is not None:
            tracker.record_failure(exc)
        return "down"
    except TimeoutError:
        if tracker is not None:
            tracker.record_failure(
                WazuhError(
                    f"Wazuh health probe {WAZUH_CHECK_TIMEOUT_SECONDS}s içinde yanıt vermedi."
                )
            )
        return "down"
    if tracker is not None:
        tracker.record_success()
    return "up"


async def _ollama_component(request: Request) -> str:
    """Ollama servisini ve model kurulumunu yoklar; durum metni döner.

    İki salt okunur çağrı: GET /api/version + GET /api/tags. Model eksikse
    "model_missing" döner — operatöre `ollama pull <tag>` ihtiyacı /ready
    üzerinden görünür olur (phases/04: model yoksa açık hata/talimat).
    """
    settings = request.app.state.settings
    if not settings.analysis_enabled:
        return "disabled"
    client = getattr(request.app.state, "ollama_client", None)
    if client is None:
        return "not_configured"
    try:
        async with asyncio.timeout(OLLAMA_CHECK_TIMEOUT_SECONDS):
            await client.check_health()
            await client.ensure_model(settings.ollama_model_tag)
    except OllamaModelMissingError:
        return "model_missing"
    except OllamaError:
        return "down"
    except TimeoutError:
        return "down"
    return "up"


@router.get("/ready")
async def readiness(request: Request) -> JSONResponse:
    """Readiness: bağımlılık durumlarını raporlar; DB kapalıysa 503 döner."""
    components: dict[str, str] = {
        "database": "up",
        "wazuh": "not_configured",
        "ollama": "not_configured",
    }

    engine = request.app.state.engine
    try:
        async with asyncio.timeout(DB_CHECK_TIMEOUT_SECONDS):
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 — herhangi bir DB hatası "down" olarak raporlanır
        components["database"] = "down"
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "components": components},
        )

    # Wazuh salt okunur probe (Faz 02): down durumunda 200 döner; panel
    # bileşen kartlarında ayrıca gösterilir (Faz 05).
    components["wazuh"] = await _wazuh_component(request)
    # Ollama probe (Faz 04): down/model_missing 200 döner (aynı gerekçe).
    components["ollama"] = await _ollama_component(request)

    return JSONResponse(
        status_code=200,
        content={"status": "ok", "components": components},
    )
