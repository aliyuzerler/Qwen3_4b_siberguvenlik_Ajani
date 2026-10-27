"""Olay listeleme ve detay endpoint'leri (Faz 05).

- GET /events      : sayfalama + filtreler (assessment, rule_level_min, q,
                     since/until, source, agent_name) — TÜMÜ sunucuda
                     doğrulanır (phases/05 "input validation").
- GET /events/{id} : tek olay + orijinal kanıt + model kaydı (ayrı nesne).

Güvenlik:
- Her iki uç da CurrentUser ister (viewer dahil her kimlik görebilir —
  tek kiracılı Faz 00 kararı); kimlik yoksa 401, ID bilinse bile.
- Arama q parametresi parameterized LIKE + kaçış (yüzde / alt çizgi / ters
  bölü) — SQL injection yok.
- XSS: backend JSON döner; HTML'e asla dönüştürmez. Zararlı içerikli log
  payload'ları aynen (string olarak) taşınır; kaçış frontend'de React'in
  otomatik metin kaçışı ile yapılır (dangerouslySetInnerHTML yasak).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func, or_, select

from app.api.v1.deps import CurrentUser, SessionDep
from app.api.v1.schemas import (
    AnalysisDetail,
    AnalysisSummary,
    EventDetail,
    EventListItem,
    EventListResponse,
    EvidenceItem,
)
from app.models.analysis import STATUS_ANALYSIS_FAILED, STATUS_COMPLETED, Analysis
from app.models.event import Event

router = APIRouter(tags=["events"])

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 25


def _escape_like(value: str) -> str:
    """LIKE joker karakterlerini kaçar (kullanıcı girdisi harfiyen aranır)."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _analysis_summary(analysis: Analysis | None) -> AnalysisSummary | None:
    if analysis is None:
        return None
    return AnalysisSummary(
        status=analysis.status,  # type: ignore[arg-type]
        ai_assessment=analysis.ai_assessment,
        confidence=analysis.confidence,
        requires_human_review=None
        if analysis.requires_human_review is None
        else bool(analysis.requires_human_review),
        model_tag=analysis.model_tag,
        finished_at=analysis.finished_at,
    )


def _analysis_detail(analysis: Analysis | None) -> AnalysisDetail | None:
    if analysis is None:
        return None
    return AnalysisDetail(
        status=analysis.status,  # type: ignore[arg-type]
        ai_assessment=analysis.ai_assessment,
        confidence=analysis.confidence,
        requires_human_review=None
        if analysis.requires_human_review is None
        else bool(analysis.requires_human_review),
        model_tag=analysis.model_tag,
        finished_at=analysis.finished_at,
        summary=analysis.summary,
        evidence=[
            EvidenceItem.model_validate(item) for item in (analysis.evidence or [])
        ],
        alternative_explanations=list(analysis.alternative_explanations or []),
        recommended_next_steps=list(analysis.recommended_next_steps or []),
        error_code=analysis.error_code,
        error_message=analysis.error_message,
        prompt_template_version=analysis.prompt_template_version,
        duration_ms=analysis.duration_ms,
        retries_used=analysis.retries_used,
    )


def _event_to_item(event: Event, analysis: Analysis | None) -> EventListItem:
    return EventListItem(
        id=str(event.id),
        timestamp=event.timestamp,
        source=event.source,
        alert_id=event.alert_id,
        agent_id=event.agent_id,
        agent_name=event.agent_name,
        manager=event.manager,
        rule_id=event.rule_id,
        rule_level=event.rule_level,
        rule_description=event.rule_description,
        rule_groups=list(event.rule_groups or []),
        seen_count=event.seen_count,
        variant_count=event.variant_count,
        analysis=_analysis_summary(analysis),
    )


@router.get("/events", response_model=EventListResponse)
async def list_events(
    request: Request,
    session: SessionDep,
    current_user: CurrentUser,
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    assessment: str | None = Query(
        default=None,
        pattern="^(completed|analysis_failed|none)$",
        description="Model kaydı durumu: completed / analysis_failed / none (analiz yok).",
    ),
    rule_level_min: int | None = Query(default=None, ge=0, le=15),
    source: str | None = Query(default=None, min_length=1, max_length=32),
    agent_name: str | None = Query(default=None, min_length=1, max_length=255),
    q: str | None = Query(default=None, min_length=1, max_length=200),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
) -> EventListResponse:
    """Sayfalı olay listesi; filtreler sunucu tarafında uygulanır."""
    del request  # Request yalnızca ileri fazlarda (cache başlıkları vb.) gerekir
    _ = current_user  # yetkilendirme dependency üzerinden yapıldı

    stmt = (
        select(Event, Analysis)
        .join(Analysis, Analysis.event_id == Event.id, isouter=True)
        .order_by(Event.timestamp.desc(), Event.id.desc())
    )

    if rule_level_min is not None:
        stmt = stmt.where(Event.rule_level >= rule_level_min)
    if source is not None:
        stmt = stmt.where(Event.source == source)
    if agent_name is not None:
        stmt = stmt.where(Event.agent_name == agent_name)
    if since is not None:
        stmt = stmt.where(Event.timestamp >= since)
    if until is not None:
        stmt = stmt.where(Event.timestamp <= until)
    if q is not None:
        escaped = f"%{_escape_like(q)}%"
        stmt = stmt.where(
            or_(
                Event.rule_description.ilike(escaped, escape="\\"),
                Event.agent_name.ilike(escaped, escape="\\"),
                Event.alert_id.ilike(escaped, escape="\\"),
            )
        )
    if assessment is not None:
        if assessment == "none":
            stmt = stmt.where(Analysis.id.is_(None))
        elif assessment == STATUS_COMPLETED:
            stmt = stmt.where(Analysis.status == STATUS_COMPLETED)
        else:
            stmt = stmt.where(Analysis.status == STATUS_ANALYSIS_FAILED)

    total: int = (await session.scalars(select(func.count()).select_from(stmt.subquery()))).one()
    pages = (total + page_size - 1) // page_size

    rows = (
        (
            await session.execute(
                stmt.offset((page - 1) * page_size).limit(page_size)
            )
        )
        .all()
    )
    return EventListResponse(
        items=[_event_to_item(event, analysis) for event, analysis in rows],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/events/{event_id}", response_model=EventDetail)
async def get_event(
    event_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> EventDetail:
    """Tek olay detayı; kimlik geçersizse ID bilinse bile 401 döner."""
    _ = current_user
    event: Event | None = (await session.scalars(select(Event).where(Event.id == event_id))).first()
    if event is None:
        raise HTTPException(status_code=404, detail="Olay bulunamadı.")
    analysis: Analysis | None = (
        await session.scalars(select(Analysis).where(Analysis.event_id == event.id))
    ).first()
    return EventDetail(
        id=str(event.id),
        timestamp=event.timestamp,
        source=event.source,
        alert_id=event.alert_id,
        agent_id=event.agent_id,
        agent_name=event.agent_name,
        manager=event.manager,
        rule_id=event.rule_id,
        rule_level=event.rule_level,
        rule_description=event.rule_description,
        rule_groups=list(event.rule_groups or []),
        seen_count=event.seen_count,
        variant_count=event.variant_count,
        location=event.location,
        decoder=event.decoder,
        src_ip=event.src_ip,
        full_log_redacted=event.full_log_redacted,
        received_at=event.received_at,
        last_seen_at=event.last_seen_at,
        analysis=_analysis_detail(analysis),
    )
