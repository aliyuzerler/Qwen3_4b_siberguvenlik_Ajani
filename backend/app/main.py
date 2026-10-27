"""FastAPI uygulama fabrikası (Faz 01 iskeleti → Faz 08 sertleştirme wiring).

Güvenli varsayılanlar:
- Uygulama, zorunlu config (JWT_SECRET, DATABASE_URL) doğrulanmadan başlamaz.
- policy_mode varsayılanı observe_only'dir; prod'da BAŞKA moda izin yoktur
  (config validator; escape hatch ayrı anahtar: REMEDIATION_PROD_ALLOW_DRY_RUN).
- Analiz worker döngüsü VARSAYILAN KAPALI'dır (WORKER_LOOP_ENABLED=false):
  operatör açmadıkça arka planda Ollama çağrısı yapılmaz.
- Analiz için mock modu YOKTUR: model erişilemezse /ready "down" raporlar ve
  analiz döngüsü event'lere sahte değerlendirme yazmadan durur.

Faz 08 sertleştirme:
- SecurityHeadersMiddleware: savunmacı yanıtlar (nosniff/DENY/no-referrer/
  no-store/CSP); HSTS yalnızca HSTS_ENABLED=true iken.
- BodySizeLimitMiddleware: istek gövdesi tavanı (413) — DoS dayanıklılığı.
- Rate limit deposu seçilebilir: memory (tek proses) | database (paylaşımlı,
  çok prosesli dağıtım; RATE_LIMIT_BACKEND).
- APP_ENV=prod'da /docs ve /openapi.json KAPALIdır (saldırı yüzeyi).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_v1_router
from app.core.config import Settings, get_settings
from app.core.db import dispose_engine, get_sessionmaker, init_engine
from app.core.logging import configure_logging, get_logger
from app.core.middleware import (
    BodySizeLimitMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
)
from app.services.analysis import build_ollama_client
from app.services.analysis.analyzer import EventAnalyzer
from app.services.analysis.metrics import AnalysisMetrics
from app.services.remediation.executor import DryRunExecutor
from app.services.security import DatabaseRateLimiter, MemoryRateLimiter, RateLimiter
from app.services.wazuh import WazuhStatusTracker, build_alert_source
from app.workers.loop import WorkerLoopStats, run_worker_loop

logger = get_logger(__name__)

API_VERSION = "0.5.0"

# Kapanışta worker task'ının temiz çıkışına tanınan süre (saniye)
WORKER_SHUTDOWN_TIMEOUT_SECONDS = 5.0


def build_analyzer(settings: Settings, client: object, metrics: AnalysisMetrics) -> EventAnalyzer:
    """Ayarlar EventAnalyzer üretir (worker döngüsü içindir)."""
    return EventAnalyzer(
        client,  # type: ignore[arg-type]  # OllamaClient protokolü
        model_tag=settings.ollama_model_tag,
        model_quantization=settings.ollama_model_quantization,
        temperature=settings.ollama_temperature,
        num_predict=settings.ollama_num_predict,
        timeout_seconds=settings.worker_timeout_seconds,
        max_retries=settings.analysis_max_retries,
        backoff_base_seconds=settings.analysis_backoff_base_seconds,
        max_context_chars=settings.analysis_max_context_chars,
        max_output_chars=settings.analysis_max_output_chars,
        concurrency=settings.worker_concurrency,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    worker_task: asyncio.Task[None] | None = None

    # Faz 05 bootstrap: users tablosu boşsa ilk admin ADMIN_BOOTSTRAP_PASSWORD
    # ile oluşturulur. Parola değeri ASLA log'a yazılmaz (yalnızca eylem adı).
    from app.services.security import bootstrap_admin_if_empty
    from app.services.security.audit import AuditAction, AuditService

    async with get_sessionmaker()() as bootstrap_session:
        created = await bootstrap_admin_if_empty(
            bootstrap_session,
            username=settings.admin_bootstrap_username,
            password=settings.admin_bootstrap_password,
        )
        if created:
            await AuditService(bootstrap_session).record(
                action=AuditAction.BOOTSTRAP_ADMIN_CREATED,
                actor=settings.admin_bootstrap_username,
                detail={"mechanism": "startup_bootstrap"},
            )

    # Faz 06: korelasyon kural kataloğunu DB'ye senkronla (upsert; sürüm
    # artışı audit'lenir; operatörün enabled kararı KORUNUR). Her başlangıçta
    # idempotent çalışır; kill switch'ten bağımsızdır (panel kuralları gösterir).
    from app.services.correlation import build_default_catalog
    from app.services.correlation.repository import CorrelationRepository

    await CorrelationRepository(get_sessionmaker()).sync_rule_catalog(
        build_default_catalog()
    )

    # Faz 07: müdahale katalog operatör anahtarlarını senkronla (idempotent;
    # default_blocked aksiyonlar enabled=false başlar — iki bağımsız kapı).
    from app.services.remediation import sync_remediation_catalog

    await sync_remediation_catalog(get_sessionmaker())

    if settings.worker_loop_enabled:
        stop_event = asyncio.Event()
        analyzer = build_analyzer(settings, app.state.ollama_client, app.state.analysis_metrics)
        stats = WorkerLoopStats()
        app.state.worker_stop = stop_event
        app.state.worker_stats = stats
        worker_task = asyncio.create_task(
            run_worker_loop(
                get_sessionmaker(),
                analyzer,
                stop_event=stop_event,
                interval_seconds=settings.worker_interval_seconds,
                batch_size=settings.analysis_batch_size,
                metrics=app.state.analysis_metrics,
                source=app.state.wazuh_source,
                policy=settings.redaction_policy,
                store_raw=settings.store_raw_alert,
                initial_window_seconds=settings.worker_initial_window_seconds,
                stats=stats,
                correlation_enabled=settings.correlation_enabled,
                correlation_lookback_seconds=settings.correlation_lookback_seconds,
                correlation_max_events=settings.correlation_max_events_per_run,
                analysis_enabled=settings.analysis_enabled,
            ),
            name="ajant-security-worker",
        )
        app.state.worker_task = worker_task
        logger.info("worker_loop_started", interval_seconds=settings.worker_interval_seconds)

    yield

    if worker_task is not None:
        shutdown_stop = getattr(app.state, "worker_stop", None)
        if shutdown_stop is not None:
            shutdown_stop.set()
        try:
            await asyncio.wait_for(worker_task, timeout=WORKER_SHUTDOWN_TIMEOUT_SECONDS)
        except TimeoutError:
            worker_task.cancel()
            await asyncio.gather(worker_task, return_exceptions=True)
        logger.info("worker_loop_stopped_signal")

    source = getattr(app.state, "wazuh_source", None)
    if source is not None:
        await source.aclose()
    ollama = getattr(app.state, "ollama_client", None)
    if ollama is not None:
        await ollama.aclose()
    await dispose_engine()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Uygulamayı güvenli varsayıllarla oluşturur."""
    app_settings = settings or get_settings()
    configure_logging(app_settings.log_level)

    application = FastAPI(
        title="ajant Security Agent API",
        version=API_VERSION,
        # Faz 08: prod'da dokümantasyon/şema uçları KAPALI (saldırı yüzeyi;
        # keşif kolaylaştırmaması). dev/staging'de açık.
        docs_url=None if app_settings.is_prod else "/docs",
        redoc_url=None if app_settings.is_prod else "/redoc",
        openapi_url=None if app_settings.is_prod else "/openapi.json",
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
    # Ollama istemcisi (Faz 04): her zaman kurulur; erişilemezse /ready "down".
    # Mock yolu yok — analiz cevabı ya gerçek modelden gelir ya da yazılmaz.
    application.state.ollama_client = build_ollama_client(
        app_settings.ollama_base_url,
        timeout_seconds=app_settings.worker_timeout_seconds,
    )
    application.state.analysis_metrics = AnalysisMetrics()
    application.state.worker_task = None  # döngü ancak lifespan'de (enabled ise) başlar

    # Faz 08: fren deposu — memory (tek proses) veya database (paylaşımlı;
    # çok prosesli dağıtımda prosesler arası tutarlı sayaç).
    if app_settings.rate_limit_backend == "database":
        application.state.auth_rate_limiter = DatabaseRateLimiter(
            get_sessionmaker(), app_settings.auth_rate_limit_per_minute
        )
        application.state.remediation_rate_limiter = DatabaseRateLimiter(
            get_sessionmaker(),
            app_settings.remediation_rate_limit_per_hour,
            window_seconds=3600.0,
        )
    else:
        application.state.auth_rate_limiter = MemoryRateLimiter(
            RateLimiter(app_settings.auth_rate_limit_per_minute)
        )
        application.state.remediation_rate_limiter = MemoryRateLimiter(
            RateLimiter(
                app_settings.remediation_rate_limit_per_hour, window_seconds=3600.0
            )
        )
    # Faz 07: yürütücü. YÜRÜTÜCÜ: DryRunExecutor — paketteki TEK somut
    # uygulama; sistemde değişiklik yapmaz (phases/07: "fake executor").
    application.state.remediation_executor = DryRunExecutor()

    application.add_middleware(RequestIdMiddleware)
    # Faz 08: savunmacı yanıt başlıkları + istek gövdesi tavanı (DoS freni).
    application.add_middleware(
        SecurityHeadersMiddleware, hsts_enabled=app_settings.hsts_enabled
    )
    application.add_middleware(
        BodySizeLimitMiddleware, max_bytes=app_settings.max_request_body_bytes
    )

    if app_settings.cors_origin_list:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=app_settings.cors_origin_list,
            # Kimlik Bearer başlığıyla taşınır (cookie oturumu YOK) →
            # credentials gerekmez; CSRF yüzeyi kapanır (Faz 05 karar).
            allow_credentials=False,
            # PATCH (Faz 06): admin korelasyon kuralı toggle'u tarayıcıdan gelir.
            allow_methods=["GET", "POST", "PATCH"],
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
        analysis_enabled=app_settings.analysis_enabled,
        worker_loop_enabled=app_settings.worker_loop_enabled,
        correlation_enabled=app_settings.correlation_enabled,
        remediation_enabled=app_settings.remediation_enabled,
        remediation_allow_blocked_actions=app_settings.remediation_allow_blocked_actions,
        rate_limit_backend=app_settings.rate_limit_backend,
        hsts_enabled=app_settings.hsts_enabled,
    )
    return application
