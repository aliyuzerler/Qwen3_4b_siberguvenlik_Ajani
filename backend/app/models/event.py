"""events tablosu ORM modeli (Faz 03).

Gereksinimler (phases/03-normalization-and-storage.md):
- UTC timestamp + idempotency key → idempotency_key UNIQUE (sha256(source:alert_id))
- Orijinal alert ID, kaynak zamanı, agent/server ve ORİJİNAL rule/severity korunur
- Model değerlendirmesi ayrı alanda → BU tabloda YOK; Faz 04'te `analyses`
  tablosu (event_id FK, ai_assessment) eklenecektir; alert verisi ile model
  çıktısı asla aynı satırda karışmaz (AGENTS.md §5, §8).
- Tekrar gelen alert aynı olayı çoğaltmaz → unique kısıt + seen_count/variant_count

Ham log çoğaltma politikası:
- full_log_redacted: maskelenmiş tam log (analiz bağlamı) — saklanır.
- raw_alert: HAM alert JSONB — yalnızca STORE_RAW_ALERT=true ise yazılır
  (varsayılan kapalı; gerekçe: docs/phase-03-verification.md § saklama).

Erişim yetkileri (belgelenmiş; compose'da uygulanan kullanıcı):
- Uygulama DB kullanıcısı: SELECT/INSERT/UPDATE(seen_count,variant_count,last_seen_at)
  DELETE yalnızca retention purge'un çalıştığı hesapta (Ajan kendi audit
  kayıtlarını değiştiremez — AGENTS.md §4; events salt-okunur felçsiz
  append-baskın tablodur).
- DDL (migration) ayrı yürütür; uygulama çalışma zamanında DDL yapmaz.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    types,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

# JSONB PostgreSQL'de, JSON diğerlerinde (sqlite test ortamı dahil).
FlexibleJSON = JSON().with_variant(JSONB(), "postgresql")


class UTCDateTime(types.TypeDecorator):
    """Okuma tarafında daima tz-bilinçli UTC datetime döner.

    Gerekçe (AGENTS.md §6: "Zamanları UTC olarak sakla"): PostgreSQL
    timestamptz aware dönerken SQLite datetime'ı naive okur; TypeDecorator
    iki backend'de de tutarlı, UTC normalize edilmiş değer garanti eder.
    Naive değer (yoksa) UTC varsayımıyla işaretlenir — Faz 02 kuralıyla aynı.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Event(Base):
    """Normalize edilmiş, sürümlenmiş güvenlik olayı (events tablosu)."""

    __tablename__ = "events"
    __table_args__ = (
        CheckConstraint("rule_level >= 0 AND rule_level <= 15", name="ck_events_rule_level"),
        Index("ix_events_source_alert_id", "source", "alert_id"),
        Index("ix_events_fingerprint", "fingerprint"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # --- Kimlik / idempotency (Faz 03: "UTC timestamp ve idempotency key") ---
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="wazuh")
    alert_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # sha256(source + ":" + alert_id) — tekil; tekrar gelen alert yeni satır üretmez.
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # --- Zaman (UTC, timezone-aware; okumada da UTC garanti) ---
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    # kaynak zamanı (Wazuh)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=_utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    # --- Orijinal rule/severity (kanonik; LLM asla üzerine yazmaz) ---
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False)
    rule_level: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-15 ORİJİNAL
    rule_description: Mapped[str] = mapped_column(String(512), nullable=False)
    rule_groups: Mapped[list[str]] = mapped_column(FlexibleJSON, nullable=False, default=list)

    # --- Kaynak/agent bilgisi (korunur) ---
    agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    manager: Mapped[str | None] = mapped_column(String(255), nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decoder: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # --- Maskelenmiş analiz bağlamı (redaction politikası uygulanmış) ---
    full_log_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # --- Idempotency takip sütunları ---
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    seen_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    variant_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # --- Ham alert (opsiyonel; STORE_RAW_ALERT=true ise dolu) ---
    raw_alert: Mapped[dict[str, object] | None] = mapped_column(FlexibleJSON, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debug kolaylığı
        return (
            f"Event(id={self.id!s}, alert_id={self.alert_id!r}, "
            f"rule_level={self.rule_level}, timestamp={self.timestamp.isoformat()})"
        )
