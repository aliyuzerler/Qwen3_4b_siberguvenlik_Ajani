"""Append-only audit kayıt servisi (Faz 05).

AGENTS.md §4: "Ajan kendi loglarını, audit kayıtlarını veya güvenlik
kontrollerini silememeli/değiştirememeli." → Bu servis YALNIZCA INSERT
yapar; UPDATE/DELETE hiçbir kod yolunda yoktur (test bunu whitelist ile
kanıtlar).

Eylem adları SABİT set'tir (AuditAction): serbest metin eylem adı audit
bütünlüğünü bozar; yeni eylem = yeni sabit (kod incelemesiyle gelir).

Kaydedilen alanlar parola/token İÇERMEZ: detail sözlüğü yapısal, küçük ve
denetlenebilirdir (örn. {"username": "admin"}); mesaj metni taşımaz.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.audit import AuditLog

logger = get_logger(__name__)


class AuditAction:
    """Sabit audit eylem adları (whitelist)."""

    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILED = "auth.login.failed"
    LOGIN_RATE_LIMITED = "auth.login.rate_limited"
    REFRESH_SUCCESS = "auth.refresh.success"
    REFRESH_FAILED = "auth.refresh.failed"
    BOOTSTRAP_ADMIN_CREATED = "auth.bootstrap.admin_created"
    # Faz 06: korelasyon kuralı sürüm senkronu ve operatör toggle izleri
    CORRELATION_RULE_SYNCED = "correlation.rule.synced"
    CORRELATION_RULE_UPDATED = "correlation.rule.updated"
    # Faz 07: müdahale hazırlık akışı (phases/07: "her aksiyonun sonucu ve
    # hata durumu audit log'a yazılsın") — redler dahil tüm geçişler izlenir.
    REMEDIATION_ACTION_PROPOSED = "remediation.action.proposed"
    REMEDIATION_ACTION_APPROVED = "remediation.action.approved"
    REMEDIATION_ACTION_REJECTED = "remediation.action.rejected"
    REMEDIATION_ACTION_EXECUTED = "remediation.action.executed"
    REMEDIATION_ACTION_FAILED = "remediation.action.failed"
    REMEDIATION_ACTION_BLOCKED = "remediation.action.blocked"
    REMEDIATION_ACTION_REPLAYED = "remediation.action.replayed"
    REMEDIATION_ACTION_RATE_LIMITED = "remediation.action.rate_limited"
    REMEDIATION_CATALOG_UPDATED = "remediation.catalog.updated"
    # Faz 08: panel kullanıcı yönetimi (admin API) ve parola işlemleri.
    # Parola DEĞERİ asla yazılmaz; yalnızca hedef kullanıcı adı + rol/is_active
    # gibi yapısal detay.
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_PASSWORD_CHANGED = "user.password_changed"  # noqa: S105  # eylem adı, parola değil
    USER_PASSWORD_RESET = "user.password_reset"  # noqa: S105  # eylem adı, parola değil


# Kod içi yazma izni: yalnızca bu sabitler audit_log.action'a yazılabilir.
ALLOWED_ACTIONS = frozenset(
    {
        AuditAction.LOGIN_SUCCESS,
        AuditAction.LOGIN_FAILED,
        AuditAction.LOGIN_RATE_LIMITED,
        AuditAction.REFRESH_SUCCESS,
        AuditAction.REFRESH_FAILED,
        AuditAction.BOOTSTRAP_ADMIN_CREATED,
        AuditAction.CORRELATION_RULE_SYNCED,
        AuditAction.CORRELATION_RULE_UPDATED,
        AuditAction.REMEDIATION_ACTION_PROPOSED,
        AuditAction.REMEDIATION_ACTION_APPROVED,
        AuditAction.REMEDIATION_ACTION_REJECTED,
        AuditAction.REMEDIATION_ACTION_EXECUTED,
        AuditAction.REMEDIATION_ACTION_FAILED,
        AuditAction.REMEDIATION_ACTION_BLOCKED,
        AuditAction.REMEDIATION_ACTION_REPLAYED,
        AuditAction.REMEDIATION_ACTION_RATE_LIMITED,
        AuditAction.REMEDIATION_CATALOG_UPDATED,
        # Faz 08: kullanıcı yönetimi
        AuditAction.USER_CREATED,
        AuditAction.USER_UPDATED,
        AuditAction.USER_PASSWORD_CHANGED,
        AuditAction.USER_PASSWORD_RESET,
    }
)

_ANONYMOUS = "anonymous"


class AuditService:
    """audit_log tablosuna INSERT yapan tek giriş noktası."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record(
        self,
        *,
        action: str,
        actor: str | None = None,
        actor_user_id: uuid.UUID | str | None = None,
        resource: str = "",
        detail: dict[str, Any] | None = None,
        client_ip: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Denetim kaydı yazar; audit hatası akışı bozmaz (loglanır).

        Giriş/refresh akışında audit yazımı başarısız olsa bile yanıt
        dönmeye devam eder — audit kilitlenme vektörüne dönüşmez; hata
        logla görünür kalır (Faz 08'de uyarı eşiği bağlanacaktır).
        """
        if action not in ALLOWED_ACTIONS:
            # Programlama hatası: sessizce yazmak yerine açık reddet.
            raise ValueError(f"Bilinmeyen audit eylemi: {action!r}")
        # actor_user_id çağıranlar str gönderebilir (AuthenticatedUser.id); Uuid
        # kolonu UUID nesnesi ister — bozuk değer kaydı DÜŞÜRMESİN, None sayılır.
        if actor_user_id is not None and not isinstance(actor_user_id, uuid.UUID):
            try:
                actor_user_id = uuid.UUID(str(actor_user_id))
            except ValueError:
                actor_user_id = None
        entry = AuditLog(
            actor=actor if actor else _ANONYMOUS,
            actor_user_id=actor_user_id,
            action=action,
            resource=resource[:128] if resource else "",
            detail=detail,
            client_ip=client_ip[:64] if client_ip else None,
            request_id=request_id[:64] if request_id else None,
        )
        try:
            self._session.add(entry)
            await self._session.commit()
        except Exception:
            await self._session.rollback()
            logger.exception("audit_write_failed", action=action)
