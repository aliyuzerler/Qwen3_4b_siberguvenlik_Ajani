"""Genel bakış endpoint'i (Faz 05).

GET /overview — panel ana sayfası verisi:
- components: DB / Wazuh / Ollama durumu (health.py probe mantığıyla aynı)
- counts: toplam olay, son 24 saat, tamamlanan/başarısız/bekleyen analiz
- by_assessment: model değerlendirme dağılımı (yalnızca completed satırlar)
- recent: son 10 olay (liste öğesi biçimi)
- model: model künyesi

Erişim: kimlik zorunlu (viewer+). Probe'lar /ready ile aynı yardımcıları
kullanır; iki kez yoklama maliyeti kabul edilebilir (3s zaman aşımı,
panel ilk yüklemesi).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request
from sqlalchemy import func, select

from app.api.v1.deps import CurrentUser, SessionDep
from app.api.v1.events import _event_to_item
from app.api.v1.health import _ollama_component, _wazuh_component
from app.api.v1.schemas import (
    ComponentStatus,
    ModelInfo,
    OverviewByAssessment,
    OverviewCounts,
    OverviewResponse,
)
from app.models.analysis import STATUS_ANALYSIS_FAILED, STATUS_COMPLETED, Analysis
from app.models.event import Event

router = APIRouter(tags=["overview"])

RECENT_LIMIT = 10
ASSESSMENT_VALUES = ("benign", "suspicious", "malicious", "unknown")


@router.get("/overview", response_model=OverviewResponse)
async def overview(
    request: Request, session: SessionDep, current_user: CurrentUser
) -> OverviewResponse:
    """Panel ana sayfası verisi (health + sayaçlar + son olaylar)."""
    _ = current_user

    components = ComponentStatus(
        database="up",  # bu istek DB oturumuyle geldi; erişilemeseydi 500 olurdu
        wazuh=await _wazuh_component(request),
        ollama=await _ollama_component(request),
    )

    since_24h = datetime.now(UTC) - timedelta(hours=24)
    total_events: int = (
        await session.scalars(select(func.count()).select_from(Event))
    ).one()
    events_24h: int = (
        await session.scalars(
            select(func.count()).select_from(Event).where(Event.timestamp >= since_24h)
        )
    ).one()
    analyses_completed: int = (
        await session.scalars(
            select(func.count())
            .select_from(Analysis)
            .where(Analysis.status == STATUS_COMPLETED)
        )
    ).one()
    analyses_failed: int = (
        await session.scalars(
            select(func.count())
            .select_from(Analysis)
            .where(Analysis.status == STATUS_ANALYSIS_FAILED)
        )
    ).one()

    by_assessment_rows = (
        await session.execute(
            select(Analysis.ai_assessment, func.count())
            .where(Analysis.status == STATUS_COMPLETED)
            .group_by(Analysis.ai_assessment)
        )
    ).all()
    by_assessment = OverviewByAssessment()
    for value, count in by_assessment_rows:
        if value in ASSESSMENT_VALUES:
            setattr(by_assessment, str(value), int(count))

    recent_rows = (
        (
            await session.execute(
                select(Event, Analysis)
                .join(Analysis, Analysis.event_id == Event.id, isouter=True)
                .order_by(Event.timestamp.desc(), Event.id.desc())
                .limit(RECENT_LIMIT)
            )
        )
        .all()
    )

    settings = request.app.state.settings
    return OverviewResponse(
        components=components,
        counts=OverviewCounts(
            total_events=total_events,
            events_24h=events_24h,
            analyses_completed=analyses_completed,
            analyses_failed=analyses_failed,
            pending_analysis=max(0, total_events - analyses_completed - analyses_failed),
        ),
        by_assessment=by_assessment,
        recent=[_event_to_item(event, analysis) for event, analysis in recent_rows],
        model=ModelInfo(
            model_tag=settings.ollama_model_tag,
            model_quantization=settings.ollama_model_quantization,
            analysis_enabled=settings.analysis_enabled,
            policy_mode=settings.policy_mode,
        ),
    )
