"""Korelasyon endpoint'leri (Faz 06).

- GET  /correlations            : tespit listesi (viewer dahil tüm roller)
- GET  /correlations/{id}       : tespit detayı + kanıt bağlantıları
- GET  /correlation-rules       : kural kataloğu (viewer dahil tüm roller)
- PATCH /correlation-rules/{key}: kural etkinlik anahtarı (YALNIZCA admin;
                                  değişim audit_log'a yazılır)

Güvenlik:
- Salt okunur uçlar CurrentUser ister (kimlik yoksa 401 — ID bilinse bile).
- PATCH admin kısıtı ROUTE düzeyinde dependency olarak bağlanır (audit_api
  kalıbı): viewer/analyst 403 alır; gerçek değişim + aktör audit'e yazılır.
- Kural çıktısı ile LLM yorumu ayrı taşınır: korelasyon şemalarında ai_*
  alanı YOKTUR; bağlı olayların model kayıtları olay başına ayrı nesnedir
  (AGENTS.md §5/§8 — şema seviyesinde garanti).
- Filtreler doğrulanır (uzunluk/aralık); serbest metin arama parametresi
  YOKTUR (LIKE yüzeyi yok; metin arama events API'dedir).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select

from app.api.v1.deps import CurrentUser, SessionDep, require_role
from app.api.v1.schemas import (
    AnalysisSummary,
    CorrelationDetail,
    CorrelationLinkedEvent,
    CorrelationListItem,
    CorrelationListResponse,
    CorrelationRuleItem,
    CorrelationRuleListResponse,
    CorrelationRuleUpdateRequest,
    CorrelationRuleUpdateResponse,
)
from app.models.analysis import Analysis
from app.models.correlation import Correlation, CorrelationEvent, CorrelationRule
from app.models.event import Event
from app.models.user import ROLE_ADMIN
from app.services.security.audit import AuditAction, AuditService

router = APIRouter(tags=["correlations"])

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 25


def _to_list_item(correlation: Correlation, rule_name: str) -> CorrelationListItem:
    return CorrelationListItem(
        id=str(correlation.id),
        rule_key=correlation.rule_key,
        rule_name=rule_name,
        rule_version=correlation.rule_version,
        window_start=correlation.window_start,
        window_end=correlation.window_end,
        event_count=correlation.event_count,
        max_rule_level=correlation.max_rule_level,
        hit_count=correlation.hit_count,
        first_hit_at=correlation.first_hit_at,
        last_hit_at=correlation.last_hit_at,
        evidence=dict(correlation.evidence or {}),
    )


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


@router.get("/correlations", response_model=CorrelationListResponse)
async def list_correlations(
    session: SessionDep,
    current_user: CurrentUser,
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    rule_key: str | None = Query(default=None, min_length=1, max_length=64),
    agent_name: str | None = Query(default=None, min_length=1, max_length=255),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
) -> CorrelationListResponse:
    """Sayfalı korelasyon listesi (en yeni pencere başlangıcı önce)."""
    _ = current_user  # yetkilendirme dependency üzerinden yapıldı

    stmt = (
        select(Correlation, CorrelationRule.name)
        .join(CorrelationRule, CorrelationRule.key == Correlation.rule_key)
        .order_by(Correlation.window_start.desc(), Correlation.id.desc())
    )
    if rule_key is not None:
        stmt = stmt.where(Correlation.rule_key == rule_key)
    if since is not None:
        stmt = stmt.where(Correlation.window_end >= since)
    if until is not None:
        stmt = stmt.where(Correlation.window_start <= until)
    if agent_name is not None:
        # Kanıt bağlantısı üzerinden olay agent'ına göre süz (IN alt sorgusu:
        # bir korelasyon birden çok bağlantıyla eşleşse de tek satır döner).
        stmt = stmt.where(
            Correlation.id.in_(
                select(CorrelationEvent.correlation_id)
                .join(Event, Event.id == CorrelationEvent.event_id)
                .where(Event.agent_name == agent_name)
            )
        )

    total: int = (await session.scalars(select(func.count()).select_from(stmt.subquery()))).one()
    pages = (total + page_size - 1) // page_size
    rows = (
        (await session.execute(stmt.offset((page - 1) * page_size).limit(page_size)))
        .all()
    )
    return CorrelationListResponse(
        items=[_to_list_item(correlation, name) for correlation, name in rows],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/correlations/{correlation_id}", response_model=CorrelationDetail)
async def get_correlation(
    correlation_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> CorrelationDetail:
    """Tek korelasyon: kural + pencere + kanıt + eşleşen olaylar (AI ayrı nesne)."""
    _ = current_user
    correlation: Correlation | None = (
        await session.scalars(
            select(Correlation).where(Correlation.id == correlation_id)
        )
    ).first()
    if correlation is None:
        raise HTTPException(status_code=404, detail="Korelasyon bulunamadı.")
    rule_name_row = (
        await session.execute(
            select(CorrelationRule.name).where(
                CorrelationRule.key == correlation.rule_key
            )
        )
    ).first()
    rule_name = rule_name_row[0] if rule_name_row else correlation.rule_key

    linked = (
        (
            await session.execute(
                select(Event, Analysis)
                .join(CorrelationEvent, CorrelationEvent.event_id == Event.id)
                .join(Analysis, Analysis.event_id == Event.id, isouter=True)
                .where(CorrelationEvent.correlation_id == correlation.id)
                .order_by(Event.timestamp.asc(), Event.id.asc())
            )
        )
        .all()
    )
    events = [
        CorrelationLinkedEvent(
            id=str(event.id),
            timestamp=event.timestamp,
            alert_id=event.alert_id,
            rule_id=event.rule_id,
            rule_level=event.rule_level,
            rule_description=event.rule_description,
            agent_name=event.agent_name,
            src_ip=event.src_ip,
            analysis=_analysis_summary(analysis),
        )
        for event, analysis in linked
    ]
    return CorrelationDetail(
        id=str(correlation.id),
        rule_key=correlation.rule_key,
        rule_name=rule_name,
        rule_version=correlation.rule_version,
        window_start=correlation.window_start,
        window_end=correlation.window_end,
        event_count=correlation.event_count,
        max_rule_level=correlation.max_rule_level,
        hit_count=correlation.hit_count,
        first_hit_at=correlation.first_hit_at,
        last_hit_at=correlation.last_hit_at,
        evidence=dict(correlation.evidence or {}),
        created_at=correlation.created_at,
        events=events,
    )


@router.get("/correlation-rules", response_model=CorrelationRuleListResponse)
async def list_correlation_rules(
    session: SessionDep, current_user: CurrentUser
) -> CorrelationRuleListResponse:
    """Kural kataloğu (sürümler + params + etkinlik; secret yok)."""
    _ = current_user
    rules = (
        await session.scalars(select(CorrelationRule).order_by(CorrelationRule.key))
    ).all()
    return CorrelationRuleListResponse(
        items=[
            CorrelationRuleItem(
                key=rule.key,
                name=rule.name,
                description=rule.description,
                version=rule.version,
                kind=rule.kind,
                params=dict(rule.params or {}),
                enabled=bool(rule.enabled),
                created_at=rule.created_at,
                updated_at=rule.updated_at,
            )
            for rule in rules
        ]
    )


@router.patch(
    "/correlation-rules/{key}",
    response_model=CorrelationRuleUpdateResponse,
    dependencies=[Depends(require_role(ROLE_ADMIN))],
)
async def update_correlation_rule(
    key: str,
    payload: CorrelationRuleUpdateRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> CorrelationRuleUpdateResponse:
    """Kural etkinlik anahtarını değiştirir (admin; audit'li).

    - Bilinmeyen anahtar → 404 (katalog içi keşif yüzeyi dar).
    - Değer değişmiyor → 200 + result="unchanged" (audit gürültüsü yok).
    - Gerçek değişim → audit CORRELATION_RULE_UPDATED (aktör = istek sahibi).
    """
    rule = await session.get(CorrelationRule, key)
    if rule is None:
        raise HTTPException(status_code=404, detail="Kural bulunamadı.")
    result = "unchanged"
    if bool(rule.enabled) != payload.enabled:
        rule.enabled = payload.enabled
        await session.commit()
        result = "updated"
        await AuditService(session).record(
            action=AuditAction.CORRELATION_RULE_UPDATED,
            actor=current_user.username,
            actor_user_id=current_user.id,
            resource=f"correlation_rule:{key}",
            detail={"enabled": payload.enabled},
        )
    return CorrelationRuleUpdateResponse(
        key=rule.key, enabled=bool(rule.enabled), result=result
    )
