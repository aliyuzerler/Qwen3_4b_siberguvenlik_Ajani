"""FastAPI uygulama fabrikası (Faz 01 iskeleti).

Güvenli varsayılanlar:
- Uygulama, zorunlu config (JWT_SECRET, DATABASE_URL) doğrulanmadan başlamaz.
- policy_mode varsayılanı observe_only'dir; Faz 07'ye kadar hiçbir müdahale yolu yoktur.
- Wazuh, Ollama ve remediation modülleri bu fazda kasıtlı olarak BAĞLI DEĞİLDİR
  (phases/01-project-skeleton.md gereği).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_v1_router
from app.core.config import Settings, get_settings
from app.core.db import dispose_engine, init_engine
from app.core.logging import configure_logging, get_logger
from app.core.middleware import RequestIdMiddleware
from app.services.wazuh import WazuhStatusTracker, build_alert_source

logger = get_logger(__name__)

API_VERSION = "0.1.0"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    source = getattr(app.state, "wazuh_source", None)
    if source is not None:
        await source.aclose()
    await dispose_engine()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Uygulamayı güvenli varsayıllarla oluşturur."""
    app_settings = settings or get_settings()
    configure_logging(app_settings.log_level)

    application = FastAPI(
        title="ajant Security Agent API",
        version=API_VERSION,
        docs_url="/docs",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    application.state.settings = app_settings
    application.state.engine = init_engine(app_settings.database_url)
    # Wazuh alert kaynağı (Faz 02): mock-first — yapılandırılmamışsa None kalır
    # ve /ready "not_configured" raporlar. Salt okunur sözleşme: source.py
    application.state.wazuh_source = build_alert_source(app_settings)
    application.state.wazuh_status = WazuhStatusTracker(
        configured=application.state.wazuh_source is not None
    )

    application.add_middleware(RequestIdMiddleware)

    if app_settings.cors_origin_list:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=app_settings.cors_origin_list,
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

    application.include_router(api_v1_router, prefix=app_settings.api_prefix)

    @application.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Yığın izi istemciye sızmaz; correlation ID ile loglanır (AGENTS.md §4).
        logger.exception("unhandled_exception", path=str(request.url.path))
        return JSONResponse(status_code=500, content={"error": "internal_error"})

    logger.info(
        "app_started",
        app_env=app_settings.app_env,
        policy_mode=app_settings.policy_mode,
        wazuh_mode=app_settings.wazuh_source_mode,
        wazuh_configured=application.state.wazuh_source is not None,
        ollama_base_url=app_settings.ollama_base_url,
        model_tag=app_settings.ollama_model_tag,
    )
    return application
