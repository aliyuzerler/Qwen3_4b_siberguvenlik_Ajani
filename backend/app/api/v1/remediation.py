"""Müdahale hazırlık endpoint'leri (Faz 07).

Gereksinimler (phases/07-remediation-guardrails.md + kabul satırı 07):
- "Başlangıçta dry-run; allowlist; insan onayı; audit; timeout; rollback/
  kill switch" → uçlar yalnızca hazırlık (öneri) + onay + dry-run yürütme
  sağlar; gerçek sistem değişikliği yapan kod yolu YOKTUR.
- RBAC: okuma viewer+; öneri analyst+; onay/ret/yürütme/katalog toggle
  YALNIZCA admin (route-dependency kalıbı — audit_api/correlations).
- "Model eylemi doğrudan başlatamaz" → her yazı ucu kimlikli insan ister
  (CurrentUser); kimliksiz istek 401 — modelden/otomasyondan gelen her
  çağrı reddedilir.
- Redler yapılandırılmış 4xx + audit (remediation.action.blocked); rate
  limit 429 + Retry-After + audit (remediation.action.rate_limited).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import ValidationError

from app.api.v1.deps import CurrentUser, SessionDep, require_role
from app.api.v1.schemas import (
    RemediationActionDetail,
    RemediationActionListResponse,
    RemediationActionResponse,
    RemediationCatalogItem,
    RemediationCatalogResponse,
    RemediationCatalogUpdateRequest,
    RemediationCatalogUpdateResponse,
    RemediationCreateRequest,
    RemediationCreateResponse,
    RemediationDecisionRequest,
    RemediationExecuteRequest,
)
from app.models.remediation import RemediationAction
from app.models.user import ROLE_ADMIN, ROLE_ANALYST
from app.services.remediation import catalog as catalog_mod
from app.services.remediation import service as remediation_service
from app.services.remediation.catalog import ActionDefinition
from app.services.remediation.errors import (
    KillSwitchError,
    ModeBlockedError,
    PolicyBlockedError,
    RemediationError,
    StateError,
)
from app.services.remediation.executor import ActionExecutor
from app.services.security.audit import AuditAction, AuditService

router = APIRouter(tags=["remediation"])

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 25


def _client_ip(request: Request) -> str | None:
    if request.client is not None and request.client.host:
        return request.client.host[:64]
    return None


def _request_id(request: Request) -> str | None:
    return request.headers.get("X-Request-ID")


def get_remediation_executor(request: Request) -> ActionExecutor:
    """Yürütücü dependency (testler app.state üzerinden fake ile değiştirir)."""
    return request.app.state.remediation_executor


ExecutorDep = Depends(get_remediation_executor)


def _policy_error(exc: PolicyBlockedError) -> HTTPException:
    """Politika redleri → 422 (yapılandırılmış code + checks izi)."""
    return HTTPException(
        status_code=422,
        detail={"code": exc.code, "message": exc.message, **(exc.detail or {})},
    )


def _state_error(exc: StateError) -> HTTPException:
    status = 404 if exc.code == "not_found" else 409
    return HTTPException(
        status_code=status,
        detail={"code": exc.code, "message": exc.message, **(exc.detail or {})},
    )


def _to_detail(action: RemediationAction) -> RemediationActionDetail:
    return RemediationActionDetail(
        id=str(action.id),
        action_type=action.action_type,
        action_title=action.action_title,
        risk_level=action.risk_level,
        status=action.status,
        requested_by_username=action.requested_by_username,
        approved_by_username=action.approved_by_username,
        justification=action.justification,
        created_at=action.created_at,
        approved_at=action.approved_at,
        executed_at=action.executed_at,
        params=dict(action.params or {}),
        evidence=dict(action.evidence or {}),
        policy_decision=dict(action.policy_decision or {}),
        rejected_by_username=action.rejected_by_username,
        rejected_reason=action.rejected_reason,
        rejected_at=action.rejected_at,
        execution_count=action.execution_count,
        execution_result=dict(action.execution_result)
        if action.execution_result is not None
        else None,
        execution_error=action.execution_error,
        updated_at=action.updated_at,
    )


async def _audit_from_context(
    request: Request,
    session: SessionDep,
    current_user: CurrentUser,
    *,
    action: str,
    resource: str,
    detail: dict[str, object],
) -> None:
    """İstek bağlamıyla audit kaydı (IP + request_id dahil)."""
    await AuditService(session).record(
        action=action,
        actor=current_user.username,
        actor_user_id=current_user.id,
        resource=resource,
        detail=detail,
        client_ip=_client_ip(request),
        request_id=_request_id(request),
    )


# --- Katalog (viewer+) ---------------------------------------------------------


@router.get("/remediation/catalog", response_model=RemediationCatalogResponse)
async def list_remediation_catalog(
    request: Request, session: SessionDep, current_user: CurrentUser
) -> RemediationCatalogResponse:
    """Allowlist kataloğu + politika künyesi (secret yok)."""
    _ = current_user
    settings = request.app.state.settings
    flags = await remediation_service.get_enabled_flags(session)
    items: list[RemediationCatalogItem] = []
    for definition in catalog_mod.list_action_definitions():
        json_schema = definition.param_model.model_json_schema()
        json_schema.pop("title", None)
        items.append(
            RemediationCatalogItem(
                action_type=definition.key,
                title=definition.title,
                description=definition.description,
                risk_level=definition.risk_level,
                default_blocked=definition.default_blocked,
                enabled=flags.get(definition.key, not definition.default_blocked),
                target_scope=definition.target_scope,
                param_schema=json_schema,
                risk_explanation=definition.risk_explanation,
                rollback_note=definition.rollback_note,
                blocked_detail=definition.blocked_detail,
            )
        )
    return RemediationCatalogResponse(
        items=items,
        policy_mode=settings.policy_mode,
        remediation_enabled=bool(settings.remediation_enabled),
        allow_blocked_actions=bool(settings.remediation_allow_blocked_actions),
        approval_ttl_minutes=settings.remediation_approval_ttl_minutes,
        rate_limit_per_hour=settings.remediation_rate_limit_per_hour,
    )


@router.patch(
    "/remediation/catalog/{action_type}",
    response_model=RemediationCatalogUpdateResponse,
    dependencies=[Depends(require_role(ROLE_ADMIN))],
)
async def update_remediation_catalog(
    request: Request,
    action_type: str,
    payload: RemediationCatalogUpdateRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> RemediationCatalogUpdateResponse:
    """Operatör enable anahtarı (admin; audit'li; default_blocked iki kapılı)."""
    settings = request.app.state.settings
    definition: ActionDefinition | None = catalog_mod.get_action_definition(action_type)
    if definition is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": "Aksiyon tipi katalogda yok."},
        )
    flags = await remediation_service.get_enabled_flags(session)
    current_enabled = flags.get(action_type, not definition.default_blocked)
    try:
        row = await remediation_service.set_action_enabled(
            session,
            action_type=action_type,
            enabled=payload.enabled,
            admin_username=current_user.username,
            admin_user_id=current_user.id,
            allow_blocked_actions=settings.remediation_allow_blocked_actions,
        )
    except StateError as exc:
        raise _state_error(exc) from exc
    return RemediationCatalogUpdateResponse(
        action_type=action_type,
        enabled=bool(row.enabled),
        result="updated" if current_enabled != bool(row.enabled) else "unchanged",
    )


# --- Öneri listesi / detayı (viewer+) -------------------------------------------


@router.get("/remediation/actions", response_model=RemediationActionListResponse)
async def list_remediation_actions(
    session: SessionDep,
    current_user: CurrentUser,
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    status: str | None = Query(default=None, min_length=3, max_length=16),
    action_type: str | None = Query(default=None, min_length=1, max_length=32),
) -> RemediationActionListResponse:
    """Sayfalı öneri listesi (status/action_type filtreli; en yeni önce)."""
    _ = current_user
    if status is not None and status not in {
        "proposed",
        "approved",
        "rejected",
        "expired",
        "executed",
        "failed",
    }:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_filter", "message": "Bilinmeyen status filtresi."},
        )
    if action_type is not None and catalog_mod.get_action_definition(action_type) is None:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_filter", "message": "Bilinmeyen action_type filtresi."},
        )
    rows, total = await remediation_service.list_actions(
        session, status=status, action_type=action_type, page=page, page_size=page_size
    )
    pages = (total + page_size - 1) // page_size
    return RemediationActionListResponse(
        items=[
            RemediationActionDetail(
                id=str(row.id),
                action_type=row.action_type,
                action_title=row.action_title,
                risk_level=row.risk_level,
                status=row.status,
                requested_by_username=row.requested_by_username,
                approved_by_username=row.approved_by_username,
                justification=row.justification,
                created_at=row.created_at,
                approved_at=row.approved_at,
                executed_at=row.executed_at,
                params=dict(row.params or {}),
                evidence=dict(row.evidence or {}),
                policy_decision=dict(row.policy_decision or {}),
                rejected_by_username=row.rejected_by_username,
                rejected_reason=row.rejected_reason,
                rejected_at=row.rejected_at,
                execution_count=row.execution_count,
                execution_result=dict(row.execution_result)
                if row.execution_result is not None
                else None,
                execution_error=row.execution_error,
                updated_at=row.updated_at,
            )
            for row in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/remediation/actions/{action_id}", response_model=RemediationActionDetail)
async def get_remediation_action(
    action_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> RemediationActionDetail:
    """Öneri detayı: kanıt paketi + politika izi + yürütme sonucu."""
    _ = current_user
    row = await session.get(RemediationAction, action_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": "Müdahale önerisi bulunamadı."},
        )
    return _to_detail(row)


# --- Öneri oluşturma (analyst+) --------------------------------------------------


@router.post(
    "/remediation/actions",
    response_model=RemediationCreateResponse,
    status_code=201,
    dependencies=[Depends(require_role(ROLE_ANALYST, ROLE_ADMIN))],
)
async def create_remediation_action(
    request: Request,
    payload: RemediationCreateRequest,
    response: Response,
    session: SessionDep,
    current_user: CurrentUser,
) -> RemediationCreateResponse:
    """Yeni öneri: politika motoru + kanıt paketi + audit.

    - Bilinmeyen tip / bozuk param / yanlış hedef / engelli aksiyon → 422
      (audit: remediation.action.blocked).
    - Kill switch → 503 (rate limit sayacından ÖNCE — bulgu F7: kapalı
      alt sistemin isteği tavanı harcamamalı). Rate limit → 429 + Retry-After.
    - Aynı idempotency_key tekrarı → 200 + created=false (yeni satır YOK).
    """
    settings = request.app.state.settings
    if not settings.remediation_enabled:
        # Erken reddet: kill switch'te rate limit sayacı HARCANMAZ.
        raise HTTPException(
            status_code=503,
            detail={
                "code": "kill_switch",
                "message": (
                    "Müdahale alt sistemi kill switch ile devre dışı "
                    "(REMEDIATION_ENABLED=false). Açmak için docs/remediation-runbook.md §1."
                ),
            },
        )
    limiter = request.app.state.remediation_rate_limiter
    decision = await limiter.check(f"remediation:{current_user.username}")
    if not decision.allowed:
        await _audit_from_context(
            request,
            session,
            current_user,
            action=AuditAction.REMEDIATION_ACTION_RATE_LIMITED,
            resource=f"remediation_user:{current_user.username}",
            detail={"endpoint": "create"},
        )
        raise HTTPException(
            status_code=429,
            detail={
                "code": "rate_limited",
                "message": "Müdahale öneri tavanına ulaştınız; bir süre bekleyin.",
            },
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )
    try:
        created_action_id, created = await remediation_service.create_proposal(
            session,
            settings=settings,
            requested_by_user_id=current_user.id,
            requested_by_username=current_user.username,
            action_type=payload.action_type,
            params=payload.params,
            event_ids=payload.event_ids,
            correlation_id=payload.correlation_id,
            justification=payload.justification,
            idempotency_key=payload.idempotency_key,
        )
    except KillSwitchError as exc:
        raise HTTPException(
            status_code=503, detail={"code": exc.code, "message": exc.message}
        ) from exc
    except PolicyBlockedError as exc:
        # Audit SERVİSTE yazılır (tek nokta); burada yalnızca HTTP eşlemesi.
        raise _policy_error(exc) from exc
    except ValidationError as exc:
        # Katalog şema reddi (serbest alan dahil) — yapılandırılmış 422.
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_params",
                "message": "Aksiyon parametreleri tip şemasına uymuyor.",
                "errors": exc.errors(include_url=False)[:5],
            },
        ) from exc
    except RemediationError as exc:  # pragma: no cover — türler yukarıda
        raise HTTPException(
            status_code=422, detail={"code": exc.code, "message": exc.message}
        ) from exc
    if not created:
        # Idempotency tekrarı: yeni satır yazılmadı → 200 (201 değil).
        response.status_code = 200
    # Taze okuma: audit arızası (rollback) ORM nesnesini expire edebilir.
    row = await session.get(RemediationAction, created_action_id)
    if row is None:  # pragma: no cover — az önce commit edildi
        raise RuntimeError("Öneri satırı commit sonrası okunamadı.")
    return RemediationCreateResponse(created=created, action=_to_detail(row))


# --- Onay / ret (admin; görev ayrımı servis katmanında) ---------------------------


@router.post(
    "/remediation/actions/{action_id}/approve",
    response_model=RemediationActionResponse,
    dependencies=[Depends(require_role(ROLE_ADMIN))],
)
async def approve_remediation_action(
    request: Request,
    action_id: uuid.UUID,
    payload: RemediationDecisionRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> RemediationActionResponse:
    """Onay: approved_by != requested_by; onay anı TTL başlangıcıdır."""
    settings = request.app.state.settings
    try:
        approved_id = await remediation_service.approve_action(
            session,
            settings=settings,
            action_id=action_id,
            admin_user_id=current_user.id,
            admin_username=current_user.username,
        )
    except KillSwitchError as exc:
        raise HTTPException(
            status_code=503, detail={"code": exc.code, "message": exc.message}
        ) from exc
    except StateError as exc:
        raise _state_error(exc) from exc
    # Taze okuma: audit arızası (rollback) ORM nesnesini expire edebilir.
    row = await session.get(RemediationAction, approved_id)
    if row is None:  # pragma: no cover — az önce commit edildi
        raise RuntimeError("Onaylanan satır commit sonrası okunamadı.")
    return RemediationActionResponse(action=_to_detail(row), replayed=False)


@router.post(
    "/remediation/actions/{action_id}/reject",
    response_model=RemediationActionResponse,
    dependencies=[Depends(require_role(ROLE_ADMIN))],
)
async def reject_remediation_action(
    request: Request,
    action_id: uuid.UUID,
    payload: RemediationDecisionRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> RemediationActionResponse:
    """Ret: gerekçe zorunlu (payload.reason); karar audit'e yazılır."""
    if not payload.reason or len(payload.reason.strip()) < 5:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "reason_required",
                "message": "Ret gerekçesi en az 5 karakter olmalıdır.",
            },
        )
    try:
        rejected_id = await remediation_service.reject_action(
            session,
            action_id=action_id,
            admin_user_id=current_user.id,
            admin_username=current_user.username,
            reason=payload.reason,
        )
    except StateError as exc:
        raise _state_error(exc) from exc
    row = await session.get(RemediationAction, rejected_id)
    if row is None:  # pragma: no cover — az önce commit edildi
        raise RuntimeError("Reddedilen satır commit sonrası okunamadı.")
    return RemediationActionResponse(action=_to_detail(row), replayed=False)


# --- Yürütme (admin; dry-run; replay korumalı) -------------------------------------


@router.post(
    "/remediation/actions/{action_id}/execute",
    response_model=RemediationActionResponse,
    dependencies=[Depends(require_role(ROLE_ADMIN))],
)
async def execute_remediation_action(
    request: Request,
    action_id: uuid.UUID,
    payload: RemediationExecuteRequest,
    session: SessionDep,
    current_user: CurrentUser,
    executor: ActionExecutor = ExecutorDep,
) -> RemediationActionResponse:
    """Yürütme: mode+TTL+politika yeniden değerlendirmesi + timeout'lu executor.

    - observe_only → 409 mode_blocked (kabul: başlangıçta dry-run; observe
      modda SİSTEM DEĞİŞİKLİĞİ YAPILMAZ, executor da ÇAĞRILMAZ).
    - dry_run → DryRunExecutor (simulated=true; kanıt: execution_result).
    - replay: aynı execution_key → orijinal sonuç + replayed=true.
    """
    settings = request.app.state.settings
    if not settings.remediation_enabled:
        # Erken reddet: kill switch'te rate limit sayacı HARCANMAZ (bulgu F7).
        raise HTTPException(
            status_code=503,
            detail={
                "code": "kill_switch",
                "message": (
                    "Müdahale alt sistemi kill switch ile devre dışı "
                    "(REMEDIATION_ENABLED=false). Açmak için docs/remediation-runbook.md §1."
                ),
            },
        )
    limiter = request.app.state.remediation_rate_limiter
    decision = await limiter.check(f"remediation:{current_user.username}")
    if not decision.allowed:
        await _audit_from_context(
            request,
            session,
            current_user,
            action=AuditAction.REMEDIATION_ACTION_RATE_LIMITED,
            resource=f"remediation_user:{current_user.username}",
            detail={"endpoint": "execute"},
        )
        raise HTTPException(
            status_code=429,
            detail={
                "code": "rate_limited",
                "message": "Müdahale yürütme tavanına ulaştınız; bir süre bekleyin.",
            },
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )
    try:
        executed_id, replayed = await remediation_service.execute_action(
            session,
            settings=settings,
            executor=executor,
            action_id=action_id,
            admin_user_id=current_user.id,
            admin_username=current_user.username,
            execution_key=payload.execution_key,
        )
    except KillSwitchError as exc:
        raise HTTPException(
            status_code=503, detail={"code": exc.code, "message": exc.message}
        ) from exc
    except ModeBlockedError as exc:
        # Audit SERVİSTE yazılır (tek nokta); observe_only → 409 (mod çatışması).
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": exc.message, **(exc.detail or {})},
        ) from exc
    except PolicyBlockedError as exc:
        raise _policy_error(exc) from exc
    except StateError as exc:
        raise _state_error(exc) from exc
    # Taze okuma: audit arızası (rollback) ORM nesnesini expire edebilir.
    row = await session.get(RemediationAction, executed_id)
    if row is None:  # pragma: no cover — az önce commit edildi
        raise RuntimeError("Yürütülen satır commit sonrası okunamadı.")
    return RemediationActionResponse(action=_to_detail(row), replayed=replayed)
