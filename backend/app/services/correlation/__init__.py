"""Korelasyon katmanı (Faz 06) — kural tabanlı, açıklanabilir, LLM'siz.

Genel arayüz:
- build_default_catalog : koddaki sürümlenmiş kural kataloğu
- CorrelationEngine     : saf değerlendirme (event listesi → tespitler)
- CorrelationRepository : katalog senkronu + idempotent tespit kaydı
- run_correlation_cycle : worker döngüsü adımı (workers.correlation)
"""

from __future__ import annotations

from app.services.correlation.engine import (
    CorrelationDetection,
    CorrelationEngine,
    EngineRun,
)
from app.services.correlation.repository import (
    CatalogSyncResult,
    CorrelationRepository,
    DetectionSaveResult,
    EnabledRulesResult,
    SaveOutcome,
)
from app.services.correlation.rules import (
    CorrelationParams,
    CorrelationRuleDef,
    build_default_catalog,
)

__all__ = [
    "CatalogSyncResult",
    "CorrelationDetection",
    "CorrelationEngine",
    "CorrelationParams",
    "CorrelationRepository",
    "CorrelationRuleDef",
    "DetectionSaveResult",
    "EnabledRulesResult",
    "EngineRun",
    "SaveOutcome",
    "build_default_catalog",
]
