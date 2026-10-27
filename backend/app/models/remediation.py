"""Müdahale aksiyonları ORM modeli (Faz 07).

Gereksinimler (phases/07-remediation-guardrails.md):
- "İnsan onayı ve onaylayan kullanıcı kaydı" → approved_by_user_id/
  approved_by_username/approved_at; görev ayrımı: onaylayan != öneren
  (servis katmanında zorunlu; uygulama DB kullanıcısı tek başına onay
  zincirini tamamlayamaz).
- "Eylem öncesi kanıt paketi" → evidence JSONB sunucu tarafında olay
  kayıtlarından üretilir; istemcinin gönderdiği kanıt KABUL EDİLMEZ.
- "Her aksiyonun sonucu ve hata durumu audit log'a yazılsın" → status
  makinesi + execution_result JSONB; her geçiş audit_log'a da düşer.
- "tekrar oynatılan istek" → idempotency_key UNIQUE (öneri oluşturma
  tekrarı) + execution_key UNIQUE (yürütme tekrarı; aynı anahtarla gelen
  ikinci istek orijinal sonucu `replayed=true` ile döner, çift yürütme OLMAZ).

Durum makinesi (status CHECK):
    proposed → approved → executed | failed
    proposed → rejected
    approved → expired            (TTL; yürütme anında tespit)
Satır SİLİNMEZ (append-baskın; retention events FK CASCADE'e bağlıdır).

Erişim yetkileri (belgelenmiş; compose'da uygulanan kullanıcı):
- Uygulama DB kullanıcısı: SELECT/INSERT + UPDATE yalnızca durum geçiş
  alanları (status/approval/execution). DELETE YOKTUR.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.event import FlexibleJSON, UTCDateTime

# Durum sabitleri (CHECK kısıtıyla da korunur)
STATUS_PROPOSED = "proposed"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_EXPIRED = "expired"
STATUS_EXECUTED = "executed"
STATUS_FAILED = "failed"

ALL_STATUSES: tuple[str, ...] = (
    STATUS_PROPOSED,
    STATUS_APPROVED,
    STATUS_REJECTED,
    STATUS_EXPIRED,
    STATUS_EXECUTED,
    STATUS_FAILED,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class RemediationCatalog(Base):
    """Katalog operatör anahtarı (action_type PK; tanım KOD kaynaklıdır).

    correlation_rules kalıbı: tanım koddan gelir, DB yalnızca operatörün
    enabled kararını taşır (startup senkronu idempotent upsert yapar).
    Varsayılanlar: normal aksiyonlar enabled=true; default_blocked
    (firewall/SSH/hesap) enabled=false — iki bağımsız kapı ilkesi.
    """

    __tablename__ = "remediation_catalog"

    action_type: Mapped[str] = mapped_column(String(32), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover — debug kolaylığı
        return (
            f"RemediationCatalog(action_type={self.action_type!r}, "
            f"enabled={self.enabled})"
        )


class RemediationAction(Base):
    """Tek müdahale önerisi ve yaşam döngüsü (remediation_actions)."""

    __tablename__ = "remediation_actions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('proposed', 'approved', 'rejected', 'expired', "
            "'executed', 'failed')",
            name="ck_remediation_actions_status",
        ),
        CheckConstraint(
            "action_type IN ('notify_admin', 'restart_wazuh_agent', "
            "'run_antivirus_scan', 'block_src_ip', 'isolate_host', "
            "'lock_user_account')",
            name="ck_remediation_actions_action_type",
        ),
        CheckConstraint(
            "risk_level IN ('low', 'medium', 'high')",
            name="ck_remediation_actions_risk_level",
        ),
        CheckConstraint(
            "execution_count >= 0", name="ck_remediation_actions_execution_count"
        ),
        Index("ix_remediation_actions_status", "status"),
        Index("ix_remediation_actions_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)

    # --- İstemci idempotency: aynı anahtarla öneri tekrarı yeni satır üretmez
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # --- Aksiyon kimliği (katalog kod kaynağı; CHECK enum) ---
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # Öneri anındaki katalog alanları SNAPSHOT'lanır (tanım değişse bile
    # öneri kaydı kendi karar bağlamını korur):
    action_title: Mapped[str] = mapped_column(String(128), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(8), nullable=False)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default=STATUS_PROPOSED)

    # --- Öneren (insan; API zorunlu kılır) ---
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    requested_by_username: Mapped[str] = mapped_column(String(64), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)  # gerekçe zorunlu

    # --- Tip parametreler (katalog şemasından geçmiş; serbest alan sızamaz) ---
    params: Mapped[dict[str, object]] = mapped_column(FlexibleJSON, nullable=False)

    # --- Kanıt paketi (sunucu üretimi: olay kayıtlarından; istemci kanıtı yok) ---
    evidence: Mapped[dict[str, object]] = mapped_column(FlexibleJSON, nullable=False)

    # --- Politika karar izi (checks listesi; panelde "neden" görünür) ---
    policy_decision: Mapped[dict[str, object]] = mapped_column(FlexibleJSON, nullable=False)

    # --- Onay (görev ayrımı: approved_by != requested_by; servis zorunlu kılar) ---
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    # --- Ret kararı (admin; gerekçe zorunlu) ---
    rejected_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    rejected_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # --- Yürütme (yalnızca admin; dry-run executor) ---
    # execution_key UNIQUE: yürütme tekrarı (replay) koruması — aynı anahtarla
    # gelen ikinci istek orijinal sonucu döndürür, çift yürütme OLMAZ.
    execution_key: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    executed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    execution_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    execution_result: Mapped[dict[str, object] | None] = mapped_column(
        FlexibleJSON, nullable=True
    )
    execution_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover — debug kolaylığı
        return (
            f"RemediationAction(id={self.id!s}, action_type={self.action_type!r}, "
            f"status={self.status!r})"
        )
