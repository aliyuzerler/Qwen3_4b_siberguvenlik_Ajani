"""Korelasyon deposu (Faz 06): katalog senkronu, aday event yükleme,
idempotent tespit kaydı, kanıt bağlantıları ve kural toggle.

Davranış sözleşmeleri:
- save_detection: dedup_key UNIQUE idempotency — aynı tespit yeniden
  üretilirse YENİ satır YAZILMAZ; hit_count+1, last_hit_at güncellenir ve
  eksik event bağlantıları eklenir (events.seen_count kalıbı). Eşzamanlı
  insert yarışı IntegrityError → bir kez yeniden sınıflandırma
  (kayıp güncelleme yok, Faz 03 kalıbı).
- sync_rule_catalog: koddaki katalog DB'ye upsert edilir; DB'deki enabled
  değeri KORUNUR (operatör kararı yeniden başlatmada sıfırlanmaz). Sürüm
  artışı audit'e yazılır (CORRELATION_RULE_SYNCED, actor=system).
- set_rule_enabled: admin toggle; gerçek değişimde audit yazılır
  (CORRELATION_RULE_UPDATED, actor=istek sahibi kullanıcı).

Hata modeli: DB altyapı hataları StorageError(retryable=True) olarak
yükseltilir → worker döngüsü fail-fast, aynı pencere güvenle yeniden
taranır (dedup_key sayesinde tekrar tespit yeni satır üretmez).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.logging import get_logger
from app.models.correlation import Correlation, CorrelationEvent, CorrelationRule
from app.models.event import Event
from app.services.correlation.engine import CorrelationDetection
from app.services.correlation.rules import (
    CorrelationRuleDef,
    params_from_storage,
)
from app.services.normalization.errors import StorageError
from app.services.security.audit import AuditAction, AuditService

logger = get_logger(__name__)

# Sistem aktörü: katalog senkronu kullanıcı etkileşimi değildir.
SYSTEM_ACTOR = "system"


class SaveOutcome(StrEnum):
    """Tek tespit kaydı sonucu."""

    NEW = "new"
    HIT = "hit"  # mevcut tespit yeniden görüldü (hit_count arttı)


@dataclass(frozen=True)
class DetectionSaveResult:
    correlation_id: str
    outcome: SaveOutcome


@dataclass
class CatalogSyncResult:
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)


@dataclass
class EnabledRulesResult:
    rules: list[CorrelationRuleDef] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)  # bozuk satırlar atlanır


class CorrelationRepository:
    """correlations/correlation_events/correlation_rules tablolarına yazım."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    # --- Aday event yükleme -------------------------------------------------

    async def load_candidate_events(self, *, since: datetime, limit: int) -> list[Event]:
        """Lookback penceresindeki event'leri zaman sırasıyla döndürür."""
        try:
            async with self._sessionmaker() as session:
                rows = (
                    await session.scalars(
                        select(Event)
                        .where(Event.timestamp >= since)
                        .order_by(Event.timestamp.asc(), Event.id.asc())
                        .limit(limit)
                    )
                ).all()
            return list(rows)
        except IntegrityError as exc:  # pragma: no cover — okuma yolunda beklenmez
            raise StorageError(str(exc), retryable=False) from exc
        except Exception as exc:
            raise _wrap_retryable(exc) from exc

    # --- Tespit kaydı (idempotent) -------------------------------------------

    async def save_detection(
        self, detection: CorrelationDetection, *, now: datetime
    ) -> DetectionSaveResult:
        """Tespiti kaydeder; aynı dedup_key varsa hit_count artırır."""
        try:
            return await self._save_once(detection, now)
        except IntegrityError:
            # Eşzamanlı insert yarışı: diğer transaction aynı dedup_key'i
            # ekledi. Yeni oturumla yeniden oku ve sınıflandır.
            try:
                return await self._save_once(detection, now)
            except IntegrityError as exc:
                # İkinci denemede de kısıt hatası: kalıcı veri problemi.
                raise _wrap_non_retryable() from exc

    async def _save_once(
        self, detection: CorrelationDetection, now: datetime
    ) -> DetectionSaveResult:
        try:
            async with self._sessionmaker() as session, session.begin():
                existing = (
                    await session.execute(
                        select(Correlation)
                        .where(Correlation.dedup_key == detection.dedup_key)
                        .with_for_update(skip_locked=True)
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    await session.execute(
                        update(Correlation)
                        .where(Correlation.id == existing.id)
                        .values(hit_count=Correlation.hit_count + 1, last_hit_at=now)
                    )
                    await self._link_events(session, existing.id, detection, now)
                    return DetectionSaveResult(
                        str(existing.id), SaveOutcome.HIT
                    )
                row = Correlation(
                    rule_key=detection.rule_key,
                    rule_version=detection.rule_version,
                    dedup_key=detection.dedup_key,
                    window_start=detection.window_start,
                    window_end=detection.window_end,
                    event_count=detection.event_count,
                    max_rule_level=detection.max_rule_level,
                    evidence=detection.evidence,
                    hit_count=1,
                    first_hit_at=now,
                    last_hit_at=now,
                    created_at=now,
                )
                session.add(row)
                await session.flush()
                await self._link_events(session, row.id, detection, now)
                return DetectionSaveResult(str(row.id), SaveOutcome.NEW)
        except IntegrityError:
            raise
        except Exception as exc:
            raise _wrap_retryable(exc) from exc

    async def _link_events(
        self,
        session: AsyncSession,
        correlation_id: uuid.UUID,
        detection: CorrelationDetection,
        now: datetime,
    ) -> None:
        """Eksik kanıt bağlantılarını ekler (idempotent; mevcutlar korunur)."""
        event_uuids = [uuid.UUID(eid) for eid in detection.event_ids]
        existing = set(
            await session.scalars(
                select(CorrelationEvent.event_id).where(
                    CorrelationEvent.correlation_id == correlation_id,
                    CorrelationEvent.event_id.in_(event_uuids),
                )
            )
        )
        missing = [
            CorrelationEvent(
                correlation_id=correlation_id, event_id=eid, linked_at=now
            )
            for eid in event_uuids
            if eid not in existing
        ]
        if missing:
            session.add_all(missing)

    # --- Kural kataloğu ------------------------------------------------------

    async def sync_rule_catalog(
        self,
        catalog: Sequence[CorrelationRuleDef],
        *,
        audit: bool = True,
    ) -> CatalogSyncResult:
        """Koddaki kataloğu DB'ye upsert eder (enabled DB'de korunur)."""
        result = CatalogSyncResult()
        for rule in catalog:
            async with self._sessionmaker() as session, session.begin():
                row = await session.get(CorrelationRule, rule.key)
                if row is None:
                    session.add(
                        CorrelationRule(
                            key=rule.key,
                            name=rule.name,
                            description=rule.description,
                            version=rule.version,
                            kind=rule.params.kind,
                            params=rule.params.to_storage(),
                            enabled=rule.enabled,
                        )
                    )
                    result.created.append(rule.key)
                elif row.version < rule.version:
                    from_version = row.version
                    row.name = rule.name
                    row.description = rule.description
                    row.version = rule.version
                    row.kind = rule.params.kind
                    row.params = rule.params.to_storage()
                    # enabled KORUNUR: operatör anahtarı deploy ile sıfırlanmaz.
                    result.updated.append(rule.key)
                    if audit:
                        await AuditService(session).record(
                            action=AuditAction.CORRELATION_RULE_SYNCED,
                            actor=SYSTEM_ACTOR,
                            resource=f"correlation_rule:{rule.key}",
                            detail={
                                "from_version": from_version,
                                "to_version": rule.version,
                            },
                        )
                else:
                    # Sürüm aynı ama params/name farkı varsa sürüm disiplini
                    # ihlali olabilir (kod değişti ama version artırılmadı) —
                    # sessiz drift yerine uyarı logla (AGENTS.md §9 raporlama).
                    if row.params != rule.params.to_storage():
                        logger.warning(
                            "correlation_rule_params_drift",
                            rule_key=rule.key,
                            db_version=row.version,
                            note="kod params değişmiş görünüyor; kural sürümü "
                            "artırılmadıysa DB eski params ile kalır",
                        )
                    result.unchanged.append(rule.key)
        return result

    async def load_enabled_rules(self) -> EnabledRulesResult:
        """DB'den etkin kuralları okur; bozuk params satırı atlanıp raporlanır."""
        result = EnabledRulesResult()
        async with self._sessionmaker() as session:
            rows = (
                await session.scalars(
                    select(CorrelationRule).where(CorrelationRule.enabled.is_(True))
                )
            ).all()
        for row in rows:
            try:
                params = params_from_storage(row.params)
            except ValueError as exc:
                result.errors.append(f"{row.key}: bozuk params ({exc})")
                continue
            result.rules.append(
                CorrelationRuleDef(
                    key=row.key,
                    name=row.name,
                    description=row.description,
                    version=row.version,
                    params=params,
                    enabled=True,
                )
            )
        return result


def _wrap_retryable(exc: Exception) -> StorageError:
    from sqlalchemy.exc import InterfaceError, OperationalError

    retryable = isinstance(exc, (OperationalError, InterfaceError))
    return StorageError(
        f"Korelasyon depolama hatası (retryable={retryable}).", retryable=retryable
    )


def _wrap_non_retryable() -> StorageError:
    return StorageError("Korelasyon depolama hatası (retryable=False).", retryable=False)
