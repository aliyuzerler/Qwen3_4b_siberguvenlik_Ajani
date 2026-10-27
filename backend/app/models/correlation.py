"""Korelasyon tabloları ORM modelleri (Faz 06).

Gereksinimler (phases/06-correlation-and-evaluation.md):
- Kural tabanlı korelasyon; LLM tek başına ilişkilendirme kaynağı DEĞİL.
- "Her korelasyon için hangi olayların ve hangi kuralın eşleştiğini göster"
  → correlations + correlation_events (kanıt bağlantıları): her tespit,
  eşleşen event listesini FK ile işaret eder.
- "Kural sürümü ve audit kaydı" → correlation_rules.version; sürüm
  değişimi/eylem audit_log'a yazılır (services/correlation.repository).
- "Kural çıktısı ve LLM yorumu ayrı tutulmalı" → correlations tablosunda
  HİÇBİR model/LLM alanı YOKTUR (ai_assessment yalnızca analyses tablosunda
  yaşamaya devam eder; panel/API iki katmanı ayrı nesnelerde taşır).

Tekrar (duplicate/near-duplicate) yönetimi:
- dedup_key UNIQUE: aynı kural + aynı grup + aynı pencere başlangıcı
  yeniden tespit edilirse YENİ satır YAZILMAZ; hit_count+1, last_hit_at
  güncellenir, yeni event bağlantıları eklenir (events.seen_count
  kalıbıyla aynı: sayaç güncellemesi append-baskın modeli bozmaz).
- correlation satırında UPDATE yalnızca hit_count/last_hit_at; DELETE kod
  yolu yoktur; retention events silince FK CASCADE ile temizlenir.

Erişim yetkileri (belgelenmiş; compose'da uygulanan kullanıcı):
- Uygulama DB kullanıcısı: SELECT/INSERT (üç tablo) + UPDATE yalnızca
  correlations.hit_count/last_hit_at ve correlation_rules.enabled/version
  (katalog senkronu + admin toggle). DELETE yok.
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
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.event import FlexibleJSON, UTCDateTime

# kind sütunu değerleri (CHECK kısıtıyla da korunur)
KIND_BURST = "burst"
KIND_SEQUENCE = "sequence"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CorrelationRule(Base):
    """Kural kataloğu satırı (koddaki kataloğun DB yansıması; Faz 06).

    - key: kararlı kısa kimlik (örn. "failed_login_burst") — PRIMARY KEY.
    - version: kural tanımı değiştiğinde KOD tarafında artırılır; startup
      senkronu DB satırını günceller ve audit kaydı yazar.
    - params: doğrulanmış parametre sözlüğü (window/threshold/group_by/
      filtreler) — services/correlation.rules.CorrelationParams şeması.
    - enabled: operatör anahtarı; admin PATCH endpoint'i ile değiştirilir
      ve değişiklik audit'e yazılır.
    """

    __tablename__ = "correlation_rules"
    __table_args__ = (
        CheckConstraint("version >= 1", name="ck_correlation_rules_version"),
        CheckConstraint(
            "kind IN ('burst', 'sequence')", name="ck_correlation_rules_kind"
        ),
    )

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String(512), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    params: Mapped[dict[str, object]] = mapped_column(FlexibleJSON, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover — debug kolaylığı
        return (
            f"CorrelationRule(key={self.key!r}, version={self.version}, "
            f"enabled={self.enabled})"
        )


class Correlation(Base):
    """Bir kural tespiti: kural + grup + pencere başlangıcı başına tek satır.

    LLM alanı BİLİNLİ OLARAK YOKTUR (kural çıktısı saf tutulur; model
    yorumu analyses tablosunda, olay başına ayrıdır — AGENTS.md §5/§8).
    """

    __tablename__ = "correlations"
    __table_args__ = (
        CheckConstraint("rule_version >= 1", name="ck_correlations_rule_version"),
        CheckConstraint("event_count >= 1", name="ck_correlations_event_count"),
        CheckConstraint(
            "hit_count >= 1", name="ck_correlations_hit_count"
        ),
        CheckConstraint(
            "max_rule_level >= 0 AND max_rule_level <= 15",
            name="ck_correlations_max_rule_level",
        ),
        Index("ix_correlations_window_start", "window_start"),
        Index("ix_correlations_rule_key", "rule_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)

    # Kural kimliği: FK (NO ACTION) — kural silinse bile tespit kaydı
    # korunur; kural silme kod yolu zaten yoktur (katalog kod kaynaklıdır).
    rule_key: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("correlation_rules.key"),
        nullable=False,
    )
    # Tespit anında kullanılan kural sürümü (izlenebilirlik: tanım değişse
    # bile eski tespit hangi sürümle üretildiğini gösterir).
    rule_version: Mapped[int] = mapped_column(Integer, nullable=False)

    # sha256(rule_key | grup değerleri | window_start ISO) — tekrar tespit
    # aynı olay kümesi için yeni satır üretmez (hit_count artar).
    dedup_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # Eşleşen olay kümesinin zaman aralığı (UTC; window_end = son event).
    window_start: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    window_end: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    # Eşleşen olaylardaki EN YÜKSEK ORİJİNAL Wazuh rule_level (LLM değerlendirmesi DEĞİL).
    max_rule_level: Mapped[int] = mapped_column(Integer, nullable=False)

    # Yapılandırılmış kanıt: grup alanı/değeri, agent adları, IP'ler,
    # eşleşen kural ID'leri, alert_id listesi (kanıt bağlantıları).
    evidence: Mapped[dict[str, object]] = mapped_column(FlexibleJSON, nullable=False)

    # Tekrar yönetimi: aynı dedup_key yeniden tespit edilirse sayaç artar.
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_hit_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    last_hit_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=_utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover — debug kolaylığı
        return (
            f"Correlation(id={self.id!s}, rule_key={self.rule_key!r}, "
            f"event_count={self.event_count}, hit_count={self.hit_count})"
        )


class CorrelationEvent(Base):
    """Korelasyon ↔ olay kanıt bağlantısı (birleşme tablosu).

    Her iki FK de ON DELETE CASCADE: event retention'da silinince bağlantı
    ve boşta kalan korelasyon bağları temizlenir (AGENTS.md §6 saklama
    disiplini — korelasyon olaydan bağımsız yaşamaz).
    """

    __tablename__ = "correlation_events"
    __table_args__ = (
        Index("ix_correlation_events_event_id", "event_id"),
    )

    correlation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("correlations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("events.id", ondelete="CASCADE"),
        primary_key=True,
    )
    linked_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=_utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover — debug kolaylığı
        return (
            f"CorrelationEvent(correlation_id={self.correlation_id!s}, "
            f"event_id={self.event_id!s})"
        )
