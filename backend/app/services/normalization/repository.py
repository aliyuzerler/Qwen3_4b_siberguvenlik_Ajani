"""Idempotent event saklama deposu (Faz 03).

Gereksinim: "Tekrar gelen alert aynı olayı/analizi çoğaltmasın."

Davranış (satır başına tek transaction):
- YENİ (idempotency_key yok)            → INSERT → outcome=stored
- AYNI idempotency_key, AYNI fingerprint → INSERT YOK; seen_count+1,
  last_seen_at güncellenir → outcome=duplicate (aynı olay, aynı analiz;
  Faz 04'te analiz yalnızca bir kez tetiklenir)
- AYNI idempotency_key, FARKLI fingerprint → INSERT YOK; variant_count+1 →
  outcome=variant. İLK YAZAN KAZANIR: saklanan satır değiştirilmez
  (append-baskın; LLM/panel tutarlılığı için mevcut olay korunur).
  Değişik payload teşhisi loglanır (AGENTS.md §9 raporlama).

Eşzamanlılık: idempotency_key UNIQUE kısıtı yarışı çözer; IntegrityError
alınan taraf satırı yeniden okuyup sınıflandırır (kayıp güncelleme yok).

Hata modeli (AGENTS.md §7: DB hata negatif testleri):
- Bağlantı/altyapı hatası → StorageError(retryable=True) — fail-fast;
  batch durur, aynı veri güvenle tekrar denenebilir.
- Kalıcı kısıt/veri hatası → StorageError(retryable=False).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, cast

from sqlalchemy import delete, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import (
    DBAPIError,
    IntegrityError,
    InterfaceError,
    OperationalError,
    SQLAlchemyError,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.event import Event
from app.services.normalization.errors import StorageError
from app.services.normalization.models import NormalizedEvent


def idempotency_key(source: str, alert_id: str) -> str:
    """Kaynak + orijinal alert ID'den deterministik tekil anahtar üretir.

    Wazuh alert id'si (epoch.mikrosaniye) kaynak içinde tekildir; kaynak
    öneki, ileride farklı SIEM kaynakları eklenirse çakışmayı önler.
    """
    raw = f"{source}:{alert_id}".encode()
    return hashlib.sha256(raw).hexdigest()


class StoreOutcome(StrEnum):
    """Tek event saklama sonucu."""

    STORED = "stored"
    DUPLICATE = "duplicate"
    VARIANT = "variant"


@dataclass(frozen=True)
class StoreResult:
    """Tek alert için saklama sonucu."""

    alert_id: str
    outcome: StoreOutcome
    event_id: str  # satır UUID'si (string) — duplicate/variant'ta mevcut satır


@dataclass
class StoreFailure:
    """Saklanamayan alert kaydı (hata izolasyonu için)."""

    alert_id: str
    message: str  # credential içermez; yalnızca yapısal bilgi
    retryable: bool


@dataclass
class IngestResult:
    """Batch saklama toplamı."""

    stored: int = 0
    duplicate: int = 0
    variant: int = 0
    failed: int = 0
    failures: list[StoreFailure] = field(default_factory=list)

    def total_ok(self) -> int:
        return self.stored + self.duplicate + self.variant


_RETRYABLE_EXC = (OperationalError, InterfaceError)


def _wrap_storage_error(exc: Exception) -> StorageError:
    retryable = isinstance(exc, _RETRYABLE_EXC)
    return StorageError(
        f"Veritabanı işlemi başarısız (retryable={retryable}).", retryable=retryable
    )


class EventRepository:
    """events tablosuna idempotent yazım; istek başına taze oturum kullanır."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def store_event(
        self, event: NormalizedEvent, *, raw: Mapping[str, Any] | None = None
    ) -> StoreResult:
        """Tek event'i idempotent saklar; sonucu sınıflandırır."""
        key = idempotency_key(event.source, event.alert_id)
        try:
            return await self._store_once(key, event, raw)
        except IntegrityError:
            # Eşzamanlı insert yarışı: diğer transaction satırı ekledi.
            # Yeni oturumla yeniden oku ve sınıflandır (kayıp güncelleme yok).
            return await self._store_once(key, event, raw)
        except DBAPIError as exc:
            raise _wrap_storage_error(exc) from exc
        except SQLAlchemyError as exc:
            raise _wrap_storage_error(exc) from exc

    async def _store_once(
        self,
        key: str,
        event: NormalizedEvent,
        raw: Mapping[str, Any] | None,
    ) -> StoreResult:
        now = datetime.now(UTC)
        async with self._sessionmaker() as session, session.begin():
            existing = (
                await session.execute(
                    select(Event)
                    .where(Event.idempotency_key == key)
                    .with_for_update(skip_locked=True)
                )
            ).scalar_one_or_none()
            if existing is None:
                row = Event(
                    schema_version=event.schema_version,
                    source=event.source,
                    alert_id=event.alert_id,
                    idempotency_key=key,
                    timestamp=event.timestamp,
                    received_at=now,
                    rule_id=event.rule_id,
                    rule_level=event.rule_level,
                    rule_description=event.rule_description,
                    rule_groups=list(event.rule_groups),
                    agent_id=event.agent_id,
                    agent_name=event.agent_name,
                    manager=event.manager,
                    location=event.location,
                    decoder=event.decoder,
                    full_log_redacted=event.full_log_redacted,
                    src_ip=event.src_ip,
                    fingerprint=event.fingerprint,
                    seen_count=1,
                    variant_count=0,
                    raw_alert=dict(raw) if raw is not None else None,
                )
                session.add(row)
                await session.flush()
                return StoreResult(event.alert_id, StoreOutcome.STORED, str(row.id))

            if existing.fingerprint == event.fingerprint:
                await session.execute(
                    update(Event)
                    .where(Event.id == existing.id)
                    .values(seen_count=Event.seen_count + 1, last_seen_at=now)
                )
                return StoreResult(event.alert_id, StoreOutcome.DUPLICATE, str(existing.id))

            # Aynı alert ID, farklı içerik: ilk yazan kazanır, sayaç işaretlenir.
            await session.execute(
                update(Event)
                .where(Event.id == existing.id)
                .values(variant_count=Event.variant_count + 1, last_seen_at=now)
            )
            return StoreResult(event.alert_id, StoreOutcome.VARIANT, str(existing.id))

    async def store_batch(
        self,
        events: Sequence[NormalizedEvent],
        *,
        raws: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> IngestResult:
        """Event listesini saklar; hata izolasyonu event başınadır.

        Retryable (altyapı) hatada batch derhal durur ve hata yükseltilir:
        DB kesintisinde her event için ayrı bağlantı denemesi yapılıp
        zaman kaybedilmez (AGENTS.md §8: timeout/retry disiplini).
        Kalıcı tek event hatası izole edilir, batch devam eder.
        """
        result = IngestResult()
        raws = raws or {}
        for event in events:
            try:
                outcome = await self.store_event(event, raw=raws.get(event.alert_id))
            except StorageError as exc:
                if exc.retryable:
                    raise
                result.failed += 1
                result.failures.append(
                    StoreFailure(alert_id=event.alert_id, message=exc.message, retryable=False)
                )
                continue
            match outcome.outcome:
                case StoreOutcome.STORED:
                    result.stored += 1
                case StoreOutcome.DUPLICATE:
                    result.duplicate += 1
                case StoreOutcome.VARIANT:
                    result.variant += 1
        return result


async def purge_expired_events(
    sessionmaker: async_sessionmaker[AsyncSession], *, now: datetime, days: int
) -> int:
    """Retention: `now - days` günden eski event'leri siler; silinen sayısını döner.

    Faz 04'teki analiz kayıtları (analyses) events'e FK ile bağlanacaktır ve
    ON DELETE CASCADE ile birlikte silinecektir (analiz, olaydan bağımsız
    yaşamaz; retention süresi AGENTS.md §6 gereği yapılandırılabilir).
    """
    cutoff = now - timedelta(days=days)
    async with sessionmaker() as session, session.begin():
        result = cast(
            "CursorResult[Any]",
            await session.execute(delete(Event).where(Event.timestamp < cutoff)),
        )
        return int(result.rowcount or 0)
