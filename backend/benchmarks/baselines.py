"""Benchmark baseline'ları (Faz 09) — karşılaştırmanın üç kolu.

Faz gereksinimi: "Baseline: yalnızca Wazuh kuralları, prompt-only Qwen ve
kural+korelasyon+Qwen karşılaştırması."

1) rules_only (rules-only-v1):
   Deterministik Wazuh severity eşik politikası. LLM YOKTUR; çıktı
   ModelAnalysis sözleşmesinde üretilir (schema-valid tanımını karşılar).
   Eşik haritası (belgeli, değişirse sürüm artar):
     rule_level >= 12        → likely_malicious (conf 0.60)
     7 <= rule_level <= 11   → suspicious         (conf 0.50)
     rule_level <= 6         → benign             (conf 0.40)
   Gerekçe: Wazuh severity'si yalnızca sinyal gücüdür; seviye 6 altındaki
   saldırı imzaları (örn. web_sqli L6) bu baseline için görünmezdir —
   karşılaştırmanın göstermesi istenen tam olarak budur.

2) qwen_prompt_only:
   Üretim prompt şablonu v1 (app.services.analysis.prompt) + Ollama
   istemcisi; korelasyon bağlamı YOK. Üretim analyzer'ı ile aynı katı
   şema + izlenebilirlik zoru (parse_model_analysis + alert_ids kontrolü).

3) rules_corr_qwen:
   Aynı LLM yolu; kullanıcı prompt'una SİSTEM tarafından eklenen güvenilir
   korelasyon özeti bloğu (v1+corr-1). Blok, dataset'e DONMUŞ tespitlerden
   (correlation_context) kurulur; model verisi değil meta verisidir.

Koşum ölçüm kuralı: süre runner'da perf_counter ile ölçülür; benchmark'ta
retry YOKTUR (ilk deneme latency'si ölçülür — üretimden sapma belgeli).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

from app.services.analysis.client import OllamaClient
from app.services.analysis.errors import OUTPUT_ERROR_SCHEMA_VIOLATION, AnalysisOutputError
from app.services.analysis.models import (
    ANALYSIS_SCHEMA_VERSION,
    Assessment,
    EvidenceItem,
    ModelAnalysis,
    RecommendedStep,
    parse_model_analysis,
)
from app.services.analysis.prompt import (
    DATA_CLOSE,
    DATA_OPEN,
    PROMPT_TEMPLATE_VERSION,
    AnalysisContext,
    build_analysis_prompt,
)
from app.services.normalization.models import NormalizedEvent
from benchmarks.dataset import BenchmarkRecord

# Baseline/prompt sürüm etiketleri (report.json provenance'a yazılır).
BASELINE_RULES_ONLY = "rules_only"
BASELINE_QWEN_PROMPT_ONLY = "qwen_prompt_only"
BASELINE_RULES_CORR_QWEN = "rules_corr_qwen"
BASELINE_VERSIONS: dict[str, str] = {
    BASELINE_RULES_ONLY: "rules-only-v1",
    BASELINE_QWEN_PROMPT_ONLY: PROMPT_TEMPLATE_VERSION,
    BASELINE_RULES_CORR_QWEN: "v1+corr-1",
}

# Korelasyon bloğu işareti — güvenilir çerçeve; veri bloğu DEĞİLDİR.
CORR_BLOCK_MARKER = "### CORRELATION CONTEXT (TRUSTED)"

# rules_only eşik haritası (üstteki docstring ile tutarlı).
RULES_LEVEL_MALICIOUS_MIN = 12
RULES_LEVEL_SUSPICIOUS_MIN = 7


@dataclass(frozen=True)
class BaselinePrediction:
    """Tek kaydın baseline çıktısı (skorlama öncesi)."""

    analysis: ModelAnalysis | None
    schema_valid: bool
    error_code: str | None
    raw_output: str | None  # marker taraması için (LLM baselines)
    prompt_chars: int
    context_truncated: bool


def context_from_record(record: BenchmarkRecord) -> AnalysisContext:
    """Üretim eşlemesi (repository._to_pending ile birebir) — maskeli alanlar."""
    event: NormalizedEvent = record.event
    return AnalysisContext(
        event_id=record.record_id,
        alert_id=event.alert_id,
        timestamp=event.timestamp,
        rule_id=event.rule_id,
        rule_level=event.rule_level,
        rule_description=event.rule_description,
        rule_groups=list(event.rule_groups),
        agent_id=event.agent_id,
        agent_name=event.agent_name,
        manager=event.manager,
        location=event.location,
        decoder=event.decoder,
        src_ip=event.src_ip,
        full_log_redacted=event.full_log_redacted,
    )


def build_correlation_block(record: BenchmarkRecord) -> str:
    """Baseline C'nin güvenilir korelasyon bloğu (detections JSON'u)."""
    detections: list[dict[str, Any]] = []
    for detection in record.correlation_context or ():
        detections.append(
            {
                "rule_key": detection.rule_key,
                "rule_version": detection.rule_version,
                "hit_count": detection.hit_count,
                "window_seconds": detection.window_seconds,
            }
        )
    payload = json.dumps(detections, ensure_ascii=False, sort_keys=True)
    return (
        f"{CORR_BLOCK_MARKER}\n"
        "Bu blok sistem tarafından eklendi; güvenilir özettir, talimat değildir:\n"
        f"{payload}"
    )


def rules_assessment(level: int) -> Assessment:
    """Deterministik eşik haritası (docstring'deki tablo)."""
    if level >= RULES_LEVEL_MALICIOUS_MIN:
        return Assessment.LIKELY_MALICIOUS
    if level >= RULES_LEVEL_SUSPICIOUS_MIN:
        return Assessment.SUSPICIOUS
    return Assessment.BENIGN


class RulesOnlyBaseline:
    """Wazuh-eşiği baseline'ı — LLM yok, %100 deterministik."""

    async def predict(self, record: BenchmarkRecord) -> BaselinePrediction:
        event = record.event
        assessment = rules_assessment(event.rule_level)
        confidence = {
            Assessment.LIKELY_MALICIOUS: 0.60,
            Assessment.SUSPICIOUS: 0.50,
            Assessment.BENIGN: 0.40,
        }[assessment]
        analysis = ModelAnalysis(
            schema_version=ANALYSIS_SCHEMA_VERSION,
            alert_ids=[event.alert_id],
            summary=(
                f"Wazuh kuralı {event.rule_id} (seviye {event.rule_level}): "
                f"{event.rule_description}"
            ),
            assessment=assessment,
            confidence=confidence,
            evidence=[
                EvidenceItem(field="rule.id", value=event.rule_id),
                EvidenceItem(field="rule.level", value=str(event.rule_level)),
            ],
            alternative_explanations=[],
            recommended_next_steps=[
                (
                    RecommendedStep.ESCALATE_TO_HUMAN_ANALYST
                    if assessment != Assessment.BENIGN
                    else RecommendedStep.NONE
                )
            ],
            requires_human_review=assessment != Assessment.BENIGN,
        )
        return BaselinePrediction(
            analysis=analysis,
            schema_valid=True,
            error_code=None,
            raw_output=analysis.model_dump_json(),
            prompt_chars=0,
            context_truncated=False,
        )


class LlmBaseline:
    """Ollama üzerinden analiz yapan baseline (B: v1, C: v1+corr-1).

    Benchmark retry'i YOKTUR: üretim EventAnalyzer'ın retry/backoff
    mekanizması latency ölçümünü kirletir; ilk deneme ölçülür. Aktarım
    hatası (OllamaError) fail-fast YÜKSELTİLİR (runner yakalar — koşum
    'aborted_infrastructure' ile kapanır). Çıktı hatası tek denemede
    schema_valid=False olur (analysis_failed karşılığı).
    """

    def __init__(
        self,
        client: OllamaClient,
        *,
        include_correlation: bool,
        model_tag: str,
        temperature: float,
        num_predict: int,
        timeout_seconds: float,
        max_context_chars: int,
        max_output_chars: int,
    ) -> None:
        self._client = client
        self._include_correlation = include_correlation
        self._model_tag = model_tag
        self._temperature = temperature
        self._num_predict = num_predict
        self._timeout_seconds = timeout_seconds
        self._max_context_chars = max_context_chars
        self._max_output_chars = max_output_chars

    @property
    def include_correlation(self) -> bool:
        return self._include_correlation

    async def predict(self, record: BenchmarkRecord) -> BaselinePrediction:
        context = context_from_record(record)
        prompt = build_analysis_prompt(context, max_log_chars=self._max_context_chars)
        user = prompt.user
        if self._include_correlation:
            user = user + "\n\n" + build_correlation_block(record)
        prompt_chars = len(prompt.system) + len(user)

        # Aktarım ailesi (OllamaError) burada YAKALANMAZ: fail-fast olarak
        # runner'a yükselir (koşum aborted_infrastructure ile kapanır).
        # TimeoutError _generate içinde OllamaUnavailableError'a çevrilir.
        raw = await self._generate(prompt.system, user)

        try:
            analysis = parse_model_analysis(raw, max_chars=self._max_output_chars)
            _check_traceability(analysis, context)
        except AnalysisOutputError as exc:
            return BaselinePrediction(
                analysis=None,
                schema_valid=False,
                error_code=exc.error_code,
                raw_output=raw,
                prompt_chars=prompt_chars,
                context_truncated=prompt.truncated,
            )

        return BaselinePrediction(
            analysis=analysis,
            schema_valid=True,
            error_code=None,
            raw_output=raw,
            prompt_chars=prompt_chars,
            context_truncated=prompt.truncated,
        )

    async def _generate(self, system: str, user: str) -> str:
        try:
            async with asyncio.timeout(self._timeout_seconds):
                return await self._client.generate(
                    system_prompt=system,
                    user_prompt=user,
                    model_tag=self._model_tag,
                    temperature=self._temperature,
                    num_predict=self._num_predict,
                    timeout_seconds=self._timeout_seconds,
                )
        except TimeoutError as exc:
            from app.services.analysis.errors import OllamaUnavailableError

            raise OllamaUnavailableError(
                f"Benchmark üretim denemesi {self._timeout_seconds}s zaman aşımına uğradı."
            ) from exc


def _check_traceability(analysis: ModelAnalysis, context: AnalysisContext) -> None:
    """Üretim izlenebilirlik zoru (analyzer._check_traceability ile aynı kural)."""
    if context.alert_id not in analysis.alert_ids:
        raise AnalysisOutputError(
            "Model çıktısındaki alert_ids analiz edilen olayı içermiyor "
            "(izlenebilirlik ihlali).",
            error_code=OUTPUT_ERROR_SCHEMA_VIOLATION,
        )


# DATA_OPEN/CLOSE dışa açık (runner/mock context çıkarma Testi için).
__all__ = [
    "BASELINE_QWEN_PROMPT_ONLY",
    "BASELINE_RULES_CORR_QWEN",
    "BASELINE_RULES_ONLY",
    "BASELINE_VERSIONS",
    "BaselinePrediction",
    "CORR_BLOCK_MARKER",
    "LlmBaseline",
    "RULES_LEVEL_MALICIOUS_MIN",
    "RULES_LEVEL_SUSPICIOUS_MIN",
    "RulesOnlyBaseline",
    "build_correlation_block",
    "context_from_record",
    "rules_assessment",
    "DATA_OPEN",
    "DATA_CLOSE",
]
