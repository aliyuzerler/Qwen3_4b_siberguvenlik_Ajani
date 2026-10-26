"""Sürümlenmiş ortak event modeli (Faz 03).

Gereksinim (phases/03-normalization-and-storage.md):
- "Wazuh alert'lerini ortak, sürümlenmiş bir event modeline dönüştür."
- "Orijinal alert ID'sini, kaynak zamanını, agent/server bilgisini ve orijinal
  rule/severity değerlerini koru. Model değerlendirmesini ayrı alanda tut."

Korunan alanlar:
- alert_id      → orijinal Wazuh id (epoch.mikrosaniye)
- timestamp     → kaynak zamanı, UTC normalize (tz'siz → UTC varsayımı)
- rule_id/rule_level/rule_description/rule_groups → ORİJİNAL Wazuh değerleri;
  rule_level kanonik int (0-15), LLM asla üzerine yazmaz (AGENTS.md §5)
- agent/manager/location/decoder → kaynak kimliği

Model değerlendirmesi BU modelde YOKTUR: Faz 04'te ayrı `analyses` tablosunda
`ai_assessment` olarak tutulacaktır (alert verisi ile model çıktısı asla aynı
satırda karışmaz; append-only ilkeler korunur).

schema_version: event modelinin sürümü. Alan seti değiştiğinde artırılır;
eski satırlar eski sürümle saklanmaya devam eder (geçiş dönüşümü ayrı iş).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.services.wazuh.models import normalize_timestamp

# Event model sürümü — alan seti değişirse artırılır (müşteriye dönük sözleşme).
EVENT_SCHEMA_VERSION = 1


class NormalizedEvent(BaseModel):
    """Kaynaktan bağımsız, sürümlenmiş saklama modeli (Faz 03 sözleşmesi)."""

    schema_version: int = EVENT_SCHEMA_VERSION
    source: str = "wazuh"
    # --- Orijinal alert kimliği ve kaynak zamanı (korunur) ---
    alert_id: str = Field(min_length=1)
    timestamp: datetime  # kaynak zamanı; UTC normalize edilir
    # --- Orijinal rule/severity (korunur; LLM bunlara yazamaz) ---
    rule_id: str = Field(min_length=1)
    rule_level: int = Field(ge=0, le=15)
    rule_description: str = Field(min_length=1)
    rule_groups: list[str] = Field(default_factory=list)
    # --- Kaynak/agent bilgisi (korunur) ---
    agent_id: str | None = None
    agent_name: str | None = None
    manager: str | None = None
    location: str | None = None
    decoder: str | None = None
    # --- Maskeleme sonrası içerik (redaction politikası uygulanmış) ---
    full_log_redacted: str | None = None
    src_ip: str | None = None  # politika uygulanmış değer (masked/redacted/none)

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return normalize_timestamp(value)

    @field_validator("source", "alert_id", "rule_id")
    @classmethod
    def _strip_nonempty(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("alan boş olamaz")
        return stripped

    @property
    def fingerprint(self) -> str:
        """Event içeriğinin deterministik parmak izi (sha256 hex).

        Amaç: aynı alert ID ile farklı içerik gelmesini ayırt etmek (Faz 03
        testi: "aynı ID ile değişik payload"). Parmak izi MASKELENMİŞ içerik
        üzerinden hesaplanır; ham secret'lı metin hash girdisine girmez.
        İçerikteki timestamp de dahildir → farklı zamanlı aynı ID farklı iz.
        """
        payload = self.fingerprint_payload()
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def fingerprint_payload(self) -> dict[str, Any]:
        """Fingerprint kapsamındaki alanların kanonik sözlüğünü döner.

        Kapsam: sürüm + kaynak + kimlik + orijinal rule + maskelenmiş içerik.
        Yeni alan eklenirse kapsam ve dolayısıyla fingerprint değişir; bu,
        istenen davranıştır (model sürümüyle uyumlu iz).
        """
        data = self.model_dump()
        return data
