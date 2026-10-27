"""Müdahale orkestrasyon servisi (Faz 07).

Sorumluluk ayrımı (AGENTS.md §8):
- Bu servis YÜRÜTME KARARINI vermez: deterministik politika motoru
  (policy.py) + insan onayı + yetkili backend (admin uçları) birlikte
  başlatır. Model/LLM bu pakete hiçbir yoldan erişemez.
- Kanıt paketi (build_evidence) SUNUCU TARAFINDA olay kayıtlarından
  üretilir; istemcinin gönderdiği "kanıt" kabul edilmez (iz bütünlüğü).
- Tüm redler audit'e yazılır (remediation.action.blocked); onay/yürütme/
  tekrar da audit'e yazılır (append-only; AuditService).

Durum makinesi:
    proposed --approve(admin≠öneren)--> approved --execute(admin,dry_run)--> executed|failed
    proposed --reject(admin)---------> rejected
    approved --TTL dolmuş (yürütmede)--> expired
Tekrar koruması: idempotency_key (öneri), execution_key (yürütme replay).

Ölçüler: öneri başına en fazla MAX_EVIDENCE_EVENTS kanıt olayı (bellek/
tanımlanabilirlik tavanı; faz faz belgelenmiş sınırlama kalıbı).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.logging import get_logger
from app.models.correlation import Correlation
from app.models.event import Event
from app.models.remediation import RemediationAction
from app.services.remediation import catalog as catalog_mod
from app.services.remediation.catalog import ActionDefinition
from app.services.remediation.errors import (
    KillSwitchError,
    PolicyBlockedError,
    RemediationError,
    StateError,
)
from app.services.remediation.executor import (
    ActionExecutor,
    ExecutionResult,
    execute_with_timeout,
)
from app.services.remediation.policy import (
    POLICY_MODE_DRY_RUN,
    PolicyDecision,
    evaluate_proposal,
    revalidate_for_execution,
)
from app.services.security.audit import AuditAction, AuditService

logger = get_logger(__name__)

MAX_EVIDENCE_EVENTS = 20
MAX_JUSTIFICATION_CHARS = 500

# Katalog tablosu satırı (operatör enabled anahtarı)
from app.models.remediation import RemediationCatalog  # noqa: E402


def _utcnow() -> datetime:
    return datetime.now(UTC)


# --- Katalog senkronu (startup; correlation kalıbı) --------------------------


async def sync_remediation_catalog(
    sessionmaker: Any,
    definitions: list[ActionDefinition] | None = None,
) -> int:
    """Katalog tanımlarını DB'ye senkronlar (idempotent upsert).

    - Yeni aksiyon: enabled = NOT default_blocked (engelliler kapalı başlar).
    - Mevcut satır: operatörün enabled kararı KORUNUR (tanım kod kaynaklıdır;
      enabled operatördedir — correlation_rules kalıbı).
    - Koddan çıkan aksiyon satırı SİLİNMEZ: allowlist kod tarafında
      zorunlu olduğundan artık koda girmeyen tip zaten önerilemez;
      eski öneri satırları da iz bütünlüğü için durur.
    """
    defs = definitions if definitions is not None else catalog_mod.list_action_definitions()
    created = 0
    async with sessionmaker() as session:
        for definition in defs:
            row = await session.get(RemediationCatalog, definition.key)
            if row is None:
                session.add(
                    RemediationCatalog(
                        action_type=definition.key,
                        enabled=not definition.default_blocked,
                    )
                )
                created += 1
        await session.commit()
    if created:
        logger.info("remediation_catalog_synced", created=created, total=len(defs))
    return created


# --- Katalog okuma / admin toggle --------------------------------------------


async def get_enabled_flags(session: AsyncSession) -> dict[str, bool]:
    """action_type → enabled haritası (DB'deki operatör kararı)."""
    rows = (await session.scalars(select(RemediationCatalog))).all()
    return {row.action_type: bool(row.enabled) for row in rows}


async def set_action_enabled(
    session: AsyncSession,
    *,
    action_type: str,
    enabled: bool,
    admin_username: str,
    admin_user_id: str,
    allow_blocked_actions: bool,
) -> RemediationCatalog:
    """Operatör anahtarını değiştirir; default_blocked için ek kapı ister.

    - default_blocked aksiyonu enable etmek, global env kapısı
      (REMEDIATION_ALLOW_BLOCKED_ACTIONS=true) OLMADAN mümkün değildir
      (iki bağımsız kapı — defense in depth).
    - Değişim audit'e yazılır (remediation.catalog.updated).
    """
    definition = catalog_mod.get_action_definition(action_type)
    if definition is None:
        raise StateError(
            code="not_found",
            message=f"Aksiyon tipi '{action_type}' katalogda tanımlı değil.",
        )
    row = await session.get(RemediationCatalog, action_type)
    if row is None:
        # Senkron atlanmışsa (test) satırı oluştur.
        row = RemediationCatalog(action_type=action_type, enabled=not definition.default_blocked)
        session.add(row)
        await session.flush()
    if definition.default_blocked and enabled and not allow_blocked_actions:
        raise StateError(
            code="default_blocked",
            message=definition.blocked_detail,
            detail={"action_type": action_type},
        )
    row.enabled = bool(enabled)
    await session.commit()
    await AuditService(session).record(
        action=AuditAction.REMEDIATION_CATALOG_UPDATED,
        actor=admin_username,
        actor_user_id=admin_user_id,
        resource=f"remediation_catalog:{action_type}",
        detail={"enabled": bool(enabled)},
    )
    return row


# --- Kanıt paketi (sunucu üretimi) -------------------------------------------


async def build_evidence(
    session: AsyncSession,
    *,
    definition: ActionDefinition,
    event_ids: list[str],
    correlation_id: str | None,
    policy_mode: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Kanıt paketi: seçili olay kayıtlarından sunucu tarafında üretilir.

    - event_ids 1..MAX_EVIDENCE_EVENTS; bilinmeyen id → target_not_found.
    - correlation_id verilirse varlığı doğrulanır ve pakete eklenir.
    - risk_explanation/rollback_note/risk_level KATALOKTAN anlık kopyalanır
      (öneri satırı kendi karar bağlamını korur).
    - Alanlar kasıtlı olarak minimaldir (AGENTS.md §6: yalnızca gerekli
      telemetri; log gövdesi kopyalanmaz).
    """
    if not (1 <= len(event_ids) <= MAX_EVIDENCE_EVENTS):
        raise PolicyBlockedError(
            reason="target_not_found",
            message=f"1 ile {MAX_EVIDENCE_EVENTS} arasında kanıt olayı seçilmelidir.",
            detail={"event_count": len(event_ids)},
        )
    parsed_ids: list[uuid.UUID] = []
    for raw_id in event_ids:
        try:
            parsed_ids.append(uuid.UUID(raw_id))
        except ValueError as exc:
            raise PolicyBlockedError(
                reason="target_not_found",
                message="Kanıt olay kimliği UUID biçiminde olmalıdır.",
                detail={"event_id": raw_id},
            ) from exc

    rows = (
        (await session.scalars(select(Event).where(Event.id.in_(parsed_ids))))
        .all()
    )
    if len(rows) != len(parsed_ids):
        raise PolicyBlockedError(
            reason="target_not_found",
            message="Bazı kanıt olayları veritabanında bulunamadı.",
            detail={"requested": len(parsed_ids), "found": len(rows)},
        )
    # Kullanıcının verdiği sırayı koru (izlenebilirlik)
    by_id = {row.id: row for row in rows}
    ordered = [by_id[parsed_id] for parsed_id in parsed_ids]

    correlation_ref: str | None = None
    if correlation_id is not None:
        try:
            corr_uuid = uuid.UUID(correlation_id)
        except ValueError as exc:
            raise PolicyBlockedError(
                reason="target_not_found",
                message="Korelasyon kimliği UUID biçiminde olmalıdır.",
                detail={"correlation_id": correlation_id},
            ) from exc
        correlation: Correlation | None = (
            await session.scalars(
                select(Correlation).where(Correlation.id == corr_uuid)
            )
        ).first()
        if correlation is None:
            raise PolicyBlockedError(
                reason="target_not_found",
                message="Bağlı korelasyon bulunamadı.",
                detail={"correlation_id": correlation_id},
            )
        correlation_ref = str(correlation.id)

    timestamps = [event.timestamp for event in ordered]
    evidence: dict[str, Any] = {
        "event_ids": [str(event.id) for event in ordered],
        "alert_ids": sorted({event.alert_id for event in ordered}),
        "rule_ids": sorted({event.rule_id for event in ordered}),
        "agent_ids": sorted({event.agent_id for event in ordered if event.agent_id}),
        "agent_names": sorted({event.agent_name for event in ordered if event.agent_name}),
        "src_ips": sorted({event.src_ip for event in ordered if event.src_ip}),
        "max_rule_level": max(event.rule_level for event in ordered),
        "window_start": min(timestamps).isoformat(),
        "window_end": max(timestamps).isoformat(),
        "correlation_id": correlation_ref,
        "risk_level": definition.risk_level,
        "risk_explanation": definition.risk_explanation,
        "rollback_note": definition.rollback_note,
        "policy_mode": policy_mode,
        "built_at": (now or _utcnow()).isoformat(),
    }
    return evidence


# --- Öneri oluşturma ----------------------------------------------------------


async def create_proposal(
    session: AsyncSession,
    *,
    settings: Settings,
    requested_by_user_id: str,
    requested_by_username: str,
    action_type: str,
    params: dict[str, Any],
    event_ids: list[str],
    correlation_id: str | None,
    justification: str,
    idempotency_key: str,
    now: datetime | None = None,
) -> tuple[uuid.UUID, bool]:
    """Yeni öneri satırı üretir; (action_id, created) döner.

    created=False → idempotency tekrarı: AYNI satır döner (yeni satır
    yazılmaz; yanıt `created=false` etiketiyle işaretlenir).

    Redler: kill_switch (503), unknown_action_type/invalid_params/
    action_disabled/default_blocked/target_scope/target_not_found (422 +
    audit blocked).
    """
    if not settings.remediation_enabled:
        raise KillSwitchError()

    now_value = now or _utcnow()

    # İstemci tekrarı (retry): aynı idempotency_key → mevcut satır.
    existing = (
        await session.scalars(
            select(RemediationAction).where(
                RemediationAction.idempotency_key == idempotency_key
            )
        )
    ).first()
    if existing is not None:
        return existing.id, False

    definition = catalog_mod.get_action_definition(action_type)
    if definition is None:
        await _audit_blocked(
            session,
            action_type=action_type,
            reason="unknown_action_type",
            actor=requested_by_username,
            actor_user_id=requested_by_user_id,
            detail={"action_type": action_type},
        )
        from app.services.remediation.errors import UnknownActionTypeError

        raise UnknownActionTypeError(action_type)

    enabled_flags = await get_enabled_flags(session)
    action_enabled = enabled_flags.get(action_type, not definition.default_blocked)

    evidence = await build_evidence(
        session,
        definition=definition,
        event_ids=event_ids,
        correlation_id=correlation_id,
        policy_mode=settings.policy_mode,
        now=now_value,
    )

    try:
        decision: PolicyDecision = evaluate_proposal(
            action_type,
            params,
            evidence,
            action_enabled=action_enabled,
            allow_blocked_actions=settings.remediation_allow_blocked_actions,
        )
    except PolicyBlockedError as exc:
        # Politika redleri TEK NOKTADAN audit'lenir (API katmanı tekrar yazmaz).
        await _audit_blocked(
            session,
            action_type=action_type,
            reason=exc.code,
            actor=requested_by_username,
            actor_user_id=requested_by_user_id,
            detail={"checks": exc.detail.get("checks", [])},
        )
        raise

    action = RemediationAction(
        idempotency_key=idempotency_key,
        action_type=action_type,
        action_title=definition.title,
        risk_level=definition.risk_level,
        status="proposed",
        requested_by_user_id=_as_uuid(requested_by_user_id),
        requested_by_username=requested_by_username,
        justification=justification[:MAX_JUSTIFICATION_CHARS],
        params=definition.validate_params(params),
        evidence=evidence,
        policy_decision=decision.to_dict(),
    )
    session.add(action)
    try:
        await session.commit()
    except IntegrityError:
        # Eşzamanlı aynı-anahtar yarışı (bulgu F3): UNIQUE idempotency_key
        # çakışması → idempotent yola düş (mevcut satırı döndür; 500 yok).
        await session.rollback()
        existing = (
            await session.scalars(
                select(RemediationAction).where(
                    RemediationAction.idempotency_key == idempotency_key
                )
            )
        ).first()
        if existing is None:  # pragma: no cover — UNIQUE çakışması başka sebep
            raise
        return existing.id, False
    # Audit hatası (rollback) ORM nesnelerini expire eder; ID'yi ÖNCE yakala.
    new_action_id: uuid.UUID = action.id
    await AuditService(session).record(
        action=AuditAction.REMEDIATION_ACTION_PROPOSED,
        actor=requested_by_username,
        actor_user_id=requested_by_user_id,
        resource=f"remediation_action:{new_action_id}",
        detail={
            "action_type": action_type,
            "risk_level": definition.risk_level,
            "event_count": len(evidence["event_ids"]),
        },
    )
    logger.info(
        "remediation_action_proposed",
        action_id=str(new_action_id),
        action_type=action_type,
        requested_by=requested_by_username,
        policy_mode=settings.policy_mode,
    )
    return new_action_id, True


# --- Onay / ret (görev ayrımı) -------------------------------------------------


async def approve_action(
    session: AsyncSession,
    *,
    settings: Settings,
    action_id: uuid.UUID,
    admin_user_id: str,
    admin_username: str,
    now: datetime | None = None,
) -> uuid.UUID:
    """Onaylar: approved_by != requested_by (görev ayrımı; escape hatch'li).

    REMEDIATION_ALLOW_SELF_APPROVAL=true (varsayılan false) küçük
    kurulumlar için bilinçli istisnadır; runbook'ta belgelenmiştir.
    Onay anı TTL başlangıcıdır (yürütme penceresi). action_id döner.
    """
    action = await _get_action_or_404(session, action_id)
    if action.status != "proposed":
        raise StateError(
            code="invalid_state",
            message=f"Onay yalnızca 'proposed' durumundaki önerilere yapılabilir "
            f"(mevcut durum: {action.status}).",
            detail={"status": action.status},
        )
    same_user = _as_uuid(admin_user_id) == action.requested_by_user_id
    if same_user and not settings.remediation_allow_self_approval:
        raise StateError(
            code="self_approval",
            message=(
                "Görev ayrımı: öneriyi yapan kullanıcı kendi önerisini "
                "onaylayamaz. Başka bir admin hesabı onaylamalıdır."
            ),
        )
    approved_action_type = action.action_type
    action.status = "approved"
    action.approved_by_user_id = _as_uuid(admin_user_id)
    action.approved_by_username = admin_username
    action.approved_at = now or _utcnow()
    await session.commit()
    await AuditService(session).record(
        action=AuditAction.REMEDIATION_ACTION_APPROVED,
        actor=admin_username,
        actor_user_id=admin_user_id,
        resource=f"remediation_action:{action_id}",
        detail={"action_type": approved_action_type, "approved_by": admin_username},
    )
    logger.info(
        "remediation_action_approved",
        action_id=str(action_id),
        approved_by=admin_username,
    )
    return action_id


async def reject_action(
    session: AsyncSession,
    *,
    action_id: uuid.UUID,
    admin_user_id: str,
    admin_username: str,
    reason: str,
    now: datetime | None = None,
) -> uuid.UUID:
    """Ret: gerekçe zorunlu; ret kararı audit'e yazılır. action_id döner."""
    action = await _get_action_or_404(session, action_id)
    if action.status != "proposed":
        raise StateError(
            code="invalid_state",
            message=f"Ret yalnızca 'proposed' durumundaki önerilere yapılabilir "
            f"(mevcut durum: {action.status}).",
            detail={"status": action.status},
        )
    rejected_action_type = action.action_type
    action.status = "rejected"
    action.rejected_by_username = admin_username
    action.rejected_at = now or _utcnow()
    action.rejected_reason = reason[:500]
    await session.commit()
    await AuditService(session).record(
        action=AuditAction.REMEDIATION_ACTION_REJECTED,
        actor=admin_username,
        actor_user_id=admin_user_id,
        resource=f"remediation_action:{action_id}",
        detail={"action_type": rejected_action_type},
    )
    logger.info("remediation_action_rejected", action_id=str(action_id), by=admin_username)
    return action_id


# --- Yürütme (yalnızca admin; dry-run; replay korumalı) ------------------------


async def execute_action(
    session: AsyncSession,
    *,
    settings: Settings,
    executor: ActionExecutor,
    action_id: uuid.UUID,
    admin_user_id: str,
    admin_username: str,
    execution_key: str,
    now: datetime | None = None,
) -> tuple[uuid.UUID, bool]:
    """Onaylı aksiyonu yürütür; (action_id, replayed) döner.

    Yürütme sırası (her adım audit/log izi bırakır):
      1. kill switch (503)
      2. satır + tekrar (replay) kararı
      3. durum: 'approved' değilse 409
      4. onay TTL'i: dolmuşsa status=expired + 409
      5. mode + tam politika yeniden değerlendirmesi (savunma derinliği)
      6. executor (timeout sınırlı; DryRunExecutor — simülasyon)
      7. sonuç satıra + audit'e yazılır
    """
    if not settings.remediation_enabled:
        raise KillSwitchError()

    # Satır kilidi: eşzamanlı yürütme yarışını engeller (TOCTOU; bulgu F2).
    action = await _get_action_or_404(session, action_id, lock=True)
    now_value = now or _utcnow()

    # --- Tekrar (replay) kararı ---
    if action.status in ("executed", "failed"):
        replayed_action_type = action.action_type
        replayed_status = action.status
        if execution_key == action.execution_key:
            # Aynı anahtar = istemci tekrarı: orijinal sonuç döner,
            # çift yürütme YAPILMAZ (executor çağrılmaz).
            await AuditService(session).record(
                action=AuditAction.REMEDIATION_ACTION_REPLAYED,
                actor=admin_username,
                actor_user_id=admin_user_id,
                resource=f"remediation_action:{action_id}",
                detail={"action_type": replayed_action_type, "status": replayed_status},
            )
            return action_id, True
        raise StateError(
            code="already_executed",
            message=(
                "Bu aksiyon zaten yürütülmüş; farklı idempotency anahtarıyla "
                "tekrar yürütme reddedilir."
            ),
            detail={"status": action.status},
        )

    # --- Durum makinesi ---
    if action.status == "proposed":
        raise StateError(
            code="not_approved",
            message="Eksik onay: aksiyon yürütülmeden önce admin onayı gerekir.",
        )
    if action.status != "approved":
        raise StateError(
            code="invalid_state",
            message=f"Aksiyon yürütülemez (mevcut durum: {action.status}).",
            detail={"status": action.status},
        )

    # --- Onay TTL (kabul: süresi dolmuş onay) ---
    approved_at = action.approved_at
    if approved_at is None:  # pragma: no cover — CHECK: approved ⇒ approved_at dolu
        raise StateError(code="invalid_state", message="Onay zamanı kaydı eksik.")
    ttl = timedelta(minutes=settings.remediation_approval_ttl_minutes)
    if now_value - approved_at > ttl:
        expired_action_type = action.action_type
        action.status = "expired"
        await session.commit()
        await AuditService(session).record(
            action=AuditAction.REMEDIATION_ACTION_BLOCKED,
            actor=admin_username,
            actor_user_id=admin_user_id,
            resource=f"remediation_action:{action_id}",
            detail={"reason": "approval_expired", "action_type": expired_action_type},
        )
        raise StateError(
            code="approval_expired",
            message=(
                f"Onay {settings.remediation_approval_ttl_minutes} dakika içinde "
                "yürütülmedi; onay süresi doldu. Yeni öneri oluşturulmalıdır."
            ),
        )

    # --- Politika yeniden değerlendirmesi (savunma derinliği) ---
    definition = catalog_mod.get_action_definition(action.action_type)
    if definition is None:  # pragma: no cover — katalog kodu geriye uyumlu
        raise StateError(
            code="unknown_action_type",
            message="Aksiyon tanımı katalogda artık yok; yürütme reddedildi.",
        )
    enabled_flags = await get_enabled_flags(session)
    action_enabled = enabled_flags.get(action.action_type, False)
    evidence = dict(action.evidence or {})
    params = dict(action.params or {})
    try:
        revalidate_for_execution(
            definition,
            params,
            evidence,
            action_enabled=action_enabled,
            allow_blocked_actions=settings.remediation_allow_blocked_actions,
            policy_mode=settings.policy_mode,
        )
    except PolicyBlockedError as exc:
        # Yürütme redleri de TEK NOKTADAN audit'lenir (mode_blocked dahil).
        await _audit_blocked(
            session,
            action_type=action.action_type,
            reason=exc.code,
            actor=admin_username,
            actor_user_id=admin_user_id,
            detail={"action_id": str(action.id)},
        )
        raise

    # --- Yürütme (timeout sınırlı; sistemde değişiklik YAPMAZ) ---
    result: ExecutionResult = await execute_with_timeout(
        executor,
        action_type=action.action_type,
        params=params,
        evidence=evidence,
        timeout_seconds=settings.remediation_executor_timeout_seconds,
    )

    action.status = "executed" if result.success else "failed"
    action.execution_key = execution_key
    action.executed_at = now_value
    action.execution_count = (action.execution_count or 0) + 1
    action.execution_result = {
        "success": result.success,
        "simulated": result.simulated,
        "duration_ms": result.duration_ms,
        "output": result.output,
    }
    action.execution_error = (
        None if result.success else f"{result.error_code}: {result.error_message}"
    )
    await session.commit()
    # Audit hatası (rollback) ORM nesnelerini expire eder → değerleri ÖNCE yakala.
    executed_action_type = action.action_type
    executed_status = action.status
    await AuditService(session).record(
        action=(
            AuditAction.REMEDIATION_ACTION_EXECUTED
            if result.success
            else AuditAction.REMEDIATION_ACTION_FAILED
        ),
        actor=admin_username,
        actor_user_id=admin_user_id,
        resource=f"remediation_action:{action_id}",
        detail={
            "action_type": executed_action_type,
            "simulated": result.simulated,
            "error_code": result.error_code,
            "duration_ms": result.duration_ms,
        },
    )
    logger.info(
        "remediation_action_executed",
        action_id=str(action_id),
        action_type=executed_action_type,
        status=executed_status,
        simulated=result.simulated,
        duration_ms=result.duration_ms,
    )
    return action_id, False


# --- Listeleme -----------------------------------------------------------------


async def list_actions(
    session: AsyncSession,
    *,
    status: str | None = None,
    action_type: str | None = None,
    page: int = 1,
    page_size: int = 25,
) -> tuple[list[RemediationAction], int]:
    """Sayfalı öneri listesi (en yeni önce)."""
    stmt = select(RemediationAction).order_by(
        RemediationAction.created_at.desc(), RemediationAction.id.desc()
    )
    if status is not None:
        stmt = stmt.where(RemediationAction.status == status)
    if action_type is not None:
        stmt = stmt.where(RemediationAction.action_type == action_type)
    total: int = (
        await session.scalars(select(func.count()).select_from(stmt.subquery()))
    ).one()
    rows = (
        (await session.execute(stmt.offset((page - 1) * page_size).limit(page_size)))
        .scalars()
        .all()
    )
    return list(rows), total


# --- Yardımcılar ----------------------------------------------------------------


async def _get_action_or_404(
    session: AsyncSession, action_id: uuid.UUID, *, lock: bool = False
) -> RemediationAction:
    """Satırı okur; lock=True ile SELECT ... FOR UPDATE (satır kilidi).

    Yürütme yolu (execute_action) lock=True ister: eşzamanlı iki admin
    yürütmesi aynı satırı kilitler ve durum makinesi yarışı (TOCTOU —
    bağımsız doğrulayıcı bulgusu F2) PostgreSQL'de engellenir; SQLite
    FOR UPDATE'i yok sayar (tek yazar semantiği zaten var).
    """
    stmt = select(RemediationAction).where(RemediationAction.id == action_id)
    if lock:
        stmt = stmt.with_for_update()
    action = (
        await session.scalars(stmt)
    ).first()
    if action is None:
        raise StateError(code="not_found", message="Müdahale önerisi bulunamadı.")
    return action


def _as_uuid(value: str | uuid.UUID | None) -> uuid.UUID | None:
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


async def _audit_blocked(
    session: AsyncSession,
    *,
    action_type: str,
    reason: str,
    actor: str,
    actor_user_id: str,
    detail: dict[str, Any],
) -> None:
    """Politika redlerini audit'e yazar (akış bozulmaz — AuditService sözleşmesi)."""
    await AuditService(session).record(
        action=AuditAction.REMEDIATION_ACTION_BLOCKED,
        actor=actor,
        actor_user_id=actor_user_id,
        resource=f"remediation_action_type:{action_type}",
        detail={"reason": reason, **detail},
    )


__all__ = [
    "MAX_EVIDENCE_EVENTS",
    "approve_action",
    "build_evidence",
    "create_proposal",
    "execute_action",
    "get_enabled_flags",
    "list_actions",
    "reject_action",
    "set_action_enabled",
    "sync_remediation_catalog",
    "RemediationError",
    "POLICY_MODE_DRY_RUN",
]
