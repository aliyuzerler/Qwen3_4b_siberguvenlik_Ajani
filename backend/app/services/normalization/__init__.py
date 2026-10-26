"""Normalizasyon ve depolama paketi (Faz 03).

Sorumluk (phases/03-normalization-and-storage.md):
- WazuhAlert → sürümlenmiş NormalizedEvent (kontrollü alan eşlemesi)
- Yapılandırılabilir redaction (parola/token/e-posta/IP)
- Idempotent DB saklama (tekrar gelen alert aynı olayı çoğaltmaz)
- Retention (30 gün varsayılan) purge fonksiyonu
"""

from __future__ import annotations

from app.services.normalization.errors import NormalizationError, StorageError
from app.services.normalization.models import EVENT_SCHEMA_VERSION, NormalizedEvent
from app.services.normalization.normalizer import normalize_alert
from app.services.normalization.redaction import (
    MAX_FULL_LOG_CHARS,
    RedactionPolicy,
    mask_ip,
    redact_src_ip,
    redact_text,
)
from app.services.normalization.repository import (
    EventRepository,
    IngestResult,
    StoreOutcome,
    StoreResult,
    purge_expired_events,
)

__all__ = [
    "EVENT_SCHEMA_VERSION",
    "MAX_FULL_LOG_CHARS",
    "EventRepository",
    "IngestResult",
    "NormalizationError",
    "NormalizedEvent",
    "RedactionPolicy",
    "StorageError",
    "StoreOutcome",
    "StoreResult",
    "mask_ip",
    "normalize_alert",
    "purge_expired_events",
    "redact_src_ip",
    "redact_text",
]
