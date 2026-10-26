"""Model analiz sözleşmesi: katı şema DTO'ları (Faz 04).

Gereksinimler (phases/04-qwen-analysis.md):
- Modelden istenen alanlar: schema_version, alert_ids, summary, assessment,
  confidence, evidence, alternative_explanations, recommended_next_steps,
  requires_human_review.
- "JSON Schema veya eşdeğer katı doğrulama" → Pydantic, extra="forbid":
  eksik alan, EKSTRA alan, yanlış enum, aralık dışı confidence reddedilir.
- "recommended_next_steps (yalnızca öneri türleri; serbest komut yok)" →
  enum whitelist; serbest metin/komut şema dışıdır ve REDDEDİLİR. Böylece
  model çıktısından eyleme giden hiçbir yol yoktur (AGENTS.md §4: LLM
  çıktısı güvenilir komut olarak kabul edilmez — çıktı yalnızca veridir).
- confidence "kalibre edilmiş olasılık olarak sunulmaz" → alan float 0-1;
  dokümantasyon ve panelde buna göre etiketlenir (Faz 05).

Merkezi ayrım (AGENTS.md §5): bu modüldeki hiçbir alan Wazuh severity'sini
temsil ETMEZ; `ai_assessment` modelin ayrı değerlendirmesidir ve orijinal
rule_level (events tablosunda) asla üzerine yazılmaz.
"""

from __future__ import annotations

import json
from enum import StrEnum

import pydantic
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Analiz şema sürümü — alan seti değişirse artırılır (prompt şablonuyla eşleşir).
ANALYSIS_SCHEMA_VERSION = 1

# Şema sabit uzunluk sınırları (config'den bağımsız sözleşme; prompt'ta da bildirilir)
SUMMARY_MAX_CHARS = 2000
EVIDENCE_MAX_ITEMS = 10
EVIDENCE_FIELD_MAX_CHARS = 128
EVIDENCE_VALUE_MAX_CHARS = 512
ALTERNATIVES_MAX_ITEMS = 5
ALTERNATIVE_MAX_CHARS = 512
STEPS_MAX_ITEMS = 5
ALERT_IDS_MAX_ITEMS = 50


class Assessment(StrEnum):
    """Modelin olay değerlendirmesi — yalnızca bu dört değer geçerlidir."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    INCONCLUSIVE = "inconclusive"


class RecommendedStep(StrEnum):
    """Öneri TÜRLERİ — serbest komut YOK (phases/04 zorunluluğu).

    Her değer, insan analist için bir sonraki adım kategorisidir;
    hiçbiri sistem üzerinde otomatik yürütülemez (Faz 07'ye kadar hiçbir
    yürütme yolu zaten yoktur: policy_mode=observe_only).
    """

    REVIEW_FULL_LOGS = "review_full_logs"
    CORRELATE_RELATED_EVENTS = "correlate_related_events"
    CHECK_AGENT_HEALTH = "check_agent_health"
    VERIFY_ASSET_CRITICALITY = "verify_asset_criticality"
    ESCALATE_TO_HUMAN_ANALYST = "escalate_to_human_analyst"
    UPDATE_DETECTION_CONTENT = "update_detection_content"
    NONE = "none"


class EvidenceItem(BaseModel):
    """Kanıt: alan adı + değer (phases/04: "evidence (alan adı ve değeri)")."""

    model_config = ConfigDict(extra="forbid")

    field: str = Field(min_length=1, max_length=EVIDENCE_FIELD_MAX_CHARS)
    value: str = Field(min_length=1, max_length=EVIDENCE_VALUE_MAX_CHARS)

    @field_validator("field", "value", mode="before")
    @classmethod
    def _scalar_to_str(cls, value: object) -> object:
        """Skaler kanıt değerlerini (int/float/bool) metne çevirir.

        Kanıt değeri sayı olabilir (örn. port 443); metne çevirmek bilgi
        kaybettirmez. None, dict/list gibi yapısal tipler REDDEDİLİR
        (model çöp/taşan yapı döndürürse şema ihlali sayılır).
        """
        if value is None:
            raise ValueError("evidence alanı boş olamaz")
        if isinstance(value, (dict, list)):
            raise ValueError("evidence değeri skaler olmalıdır")
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        return value

    @field_validator("field", "value")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


class ModelAnalysis(BaseModel):
    """Modelin ÜRETİMESİ istenen çıktı şeması — katı doğrulama.

    extra="forbid": modelin şema dışı alan eklemesi (örn. kendi uydurduğu
    "severity") REDDEDİLİR → retry → analysis_failed. Bu, LLM çıktısının
    asla doğrudan kabul edilmemesi ilkesinin uygulamasıdır (AGENTS.md §5).
    """

    model_config = ConfigDict(extra="forbid")

    # schema_version ZORUNLUDUR (default YOK): modelin şema sürümünü açıkça
    # bildirmesi sözleşmenin parçasıdır; eksik alan reddedilir.
    schema_version: int
    alert_ids: list[str] = Field(min_length=1, max_length=ALERT_IDS_MAX_ITEMS)
    summary: str = Field(min_length=1, max_length=SUMMARY_MAX_CHARS)
    assessment: Assessment
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EvidenceItem] = Field(max_length=EVIDENCE_MAX_ITEMS)
    alternative_explanations: list[str] = Field(
        default_factory=list, max_length=ALTERNATIVES_MAX_ITEMS
    )
    recommended_next_steps: list[RecommendedStep] = Field(
        default_factory=list, max_length=STEPS_MAX_ITEMS
    )
    requires_human_review: bool

    @field_validator("schema_version")
    @classmethod
    def _schema_version_exact(cls, value: int) -> int:
        if value != ANALYSIS_SCHEMA_VERSION:
            raise ValueError(f"schema_version {ANALYSIS_SCHEMA_VERSION} olmalıdır")
        return value

    @field_validator("alert_ids", "alternative_explanations")
    @classmethod
    def _strip_strings(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value]

    @field_validator("alert_ids")
    @classmethod
    def _alert_ids_nonempty(cls, value: list[str]) -> list[str]:
        if any(not item for item in value):
            raise ValueError("alert_ids boş öğe içeremez")
        return value

    @field_validator("summary", "alternative_explanations")
    @classmethod
    def _summary_nonempty(cls, value: str | list[str]) -> str | list[str]:
        if isinstance(value, str) and not value.strip():
            raise ValueError("summary boş olamaz")
        if isinstance(value, list) and any(not item for item in value):
            raise ValueError("alternative_explanations boş öğe içeremez")
        return value


def parse_model_analysis(raw_json: str, *, max_chars: int) -> ModelAnalysis:
    """Model çıktısı metnini katı şemayla doğrular.

    max_chars: ham çıktı tavanı (config: ANALYSIS_MAX_OUTPUT_CHARS); aşılırsa
    output_too_long koduyla reddedilir — çok uzun çıktı parse edilmez.

    Ekstra davranış: JSON dizi/skaler dönerse (nesne değil) anlaşılır hata.
    Pydantic ValidationError çağıran tarafa (analyzer) AnalysisOutputError
    olarak sarılır; burada sarılmaz — analyzer kendi hata kodu politikasını
    uygular.
    """
    from app.services.analysis.errors import (
        OUTPUT_ERROR_INVALID_JSON,
        OUTPUT_ERROR_SCHEMA_VIOLATION,
        OUTPUT_ERROR_TOO_LONG,
        AnalysisOutputError,
    )

    if len(raw_json) > max_chars:
        raise AnalysisOutputError(
            f"Model çıktısı çok uzun ({len(raw_json)} > {max_chars} karakter).",
            error_code=OUTPUT_ERROR_TOO_LONG,
        )
    try:
        payload = json.loads(raw_json)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise AnalysisOutputError(
            "Model çıktısı geçerli JSON değil (yapısal bilgi: parse hatası).",
            error_code=OUTPUT_ERROR_INVALID_JSON,
        ) from exc
    if not isinstance(payload, dict):
        raise AnalysisOutputError(
            "Model çıktısı JSON nesnesi değil (dizi/skaler reddedilir).",
            error_code=OUTPUT_ERROR_SCHEMA_VIOLATION,
        )
    try:
        return ModelAnalysis.model_validate(payload)
    except pydantic.ValidationError as exc:
        raise AnalysisOutputError(
            f"Model çıktısı şema doğrulamasını geçemedi ({_brief_violations(exc)}).",
            error_code=OUTPUT_ERROR_SCHEMA_VIOLATION,
        ) from exc


def _brief_violations(exc: pydantic.ValidationError) -> str:
    """Şema ihlali mesajını yapısal ve kısa özetler (log içeriği taşımaz)."""
    parts: list[str] = []
    for error in exc.errors()[:4]:
        loc = ".".join(str(part) for part in error.get("loc", ())) or "kök"
        parts.append(f"{loc}: {error.get('type', 'invalid')}")
    more = len(exc.errors()) - len(parts)
    summary = "; ".join(parts)
    return f"{summary} (+{more} ihlal)" if more > 0 else summary


__all__ = [
    "ALERT_IDS_MAX_ITEMS",
    "ALTERNATIVES_MAX_ITEMS",
    "ANALYSIS_SCHEMA_VERSION",
    "Assessment",
    "EvidenceItem",
    "ModelAnalysis",
    "RecommendedStep",
    "SUMMARY_MAX_CHARS",
    "parse_model_analysis",
]
