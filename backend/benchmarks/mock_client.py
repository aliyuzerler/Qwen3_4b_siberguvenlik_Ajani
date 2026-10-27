"""Deterministik mock Ollama istemcisi (Faz 09) — ALTYAPI DOĞRULAMA İÇİN.

KRİTİK UYARI (report.json'a da yazılır): bu istemcinin çıktıları model
kalitesi KANITI DEĞİLDİR. Yalnızca şu amaçlarla vardır:
- benchmark hattının (dataset → baseline → skorlama → rapor) uçtan uca
  sandbox'ta (Ollama'sız) doğrulanması,
- metrik motorunun ve CSV/JSON üretiminin test edilmesi,
- kullanıcı makinesindeki GERÇEK koşum öncesi kurulanın sağlığı.

Davranış: prompt'taki <event_data> bağlamını ayrıştırır; rules_only ile
AYNI eşik haritasını uygular; korelasyon bloğu varsa (baseline C) hit
sayısına göre kararı GÜÇLENDİRİR (hit_count >= 5 → en az suspicious,
hit_count >= 8 veya seviye >= 12 → likely_malicious). Kanıtları yalnızca
bağlamdaki gerçek alanlardan seçer; marker/çıpa uydurmaz.
"""

from __future__ import annotations

import json
from typing import Any

from app.services.analysis.errors import OllamaBadPayloadError
from app.services.analysis.models import ANALYSIS_SCHEMA_VERSION
from app.services.analysis.prompt import DATA_CLOSE, DATA_OPEN
from benchmarks.baselines import CORR_BLOCK_MARKER, rules_assessment

# Korelasyon güçlendirme eşikleri (belgeli; mock davranış sözleşmesi).
_CORR_BUMP_SUSPICIOUS_MIN_HITS = 5
_CORR_MALICIOUS_MIN_HITS = 8


class MockOllamaClient:
    """OllamaClient protokolünü karşılayan deterministik sahte istemci."""

    async def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        model_tag: str,
        temperature: float,
        num_predict: int,
        timeout_seconds: float,
    ) -> str:
        del system_prompt, model_tag, temperature, num_predict, timeout_seconds
        payload = _extract_context_payload(user_prompt)
        level = int(payload["rule"]["level"])
        rule_id = str(payload["rule"]["id"])

        assessment_value = rules_assessment(level).value
        assessment_value = _apply_correlation(user_prompt, level, assessment_value)

        evidence: list[dict[str, str]] = [{"field": "rule.id", "value": rule_id}]
        if payload.get("src_ip"):
            evidence.append({"field": "src_ip", "value": str(payload["src_ip"])})

        output = {
            "schema_version": ANALYSIS_SCHEMA_VERSION,
            "alert_ids": [str(payload["alert_id"])],
            "summary": (
                f"Sentetik dogrulama cikti: kural {rule_id} seviye {level} "
                f"(mock istemci; model kaniti degildir)."
            ),
            "assessment": assessment_value,
            "confidence": 0.5,
            "evidence": evidence,
            "alternative_explanations": [],
            "recommended_next_steps": (
                ["escalate_to_human_analyst"]
                if assessment_value != "benign"
                else ["none"]
            ),
            "requires_human_review": assessment_value != "benign",
        }
        return json.dumps(output, ensure_ascii=False, sort_keys=True)

    async def check_health(self) -> None:
        """Mock her zaman sağlıklıdır."""

    async def ensure_model(self, model_tag: str) -> None:
        """Mock model kurulumu gerektirmez."""

    async def aclose(self) -> None:
        """Kapatılacak kaynak yoktur."""


def _extract_context_payload(user_prompt: str) -> dict[str, Any]:
    """<event_data> bloğundaki bağlam JSON'unu ayrıştırır.

    Mock, benchmark'ın kendisinin ürettiği bağlam bloğuna dayanır; blok
    bulunamazsa/çözülemezse OllamaBadPayloadError (mock'un zarf hatası —
    hattın bozuk olduğunu gösterir, sessiz telafi yoktur).
    """
    start = user_prompt.find(DATA_OPEN)
    end = user_prompt.find(DATA_CLOSE)
    if start < 0 or end < 0 or end <= start:
        raise OllamaBadPayloadError("Mock istemci: <event_data> bloğu bulunamadı.")
    body = user_prompt[start + len(DATA_OPEN) : end].strip()
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise OllamaBadPayloadError("Mock istemci: bağlam JSON'u çözülemedi.") from exc
    if not isinstance(payload, dict) or "rule" not in payload or "alert_id" not in payload:
        raise OllamaBadPayloadError("Mock istemci: bağlam beklenen alanları taşımıyor.")
    return payload


def _apply_correlation(user_prompt: str, level: int, base: str) -> str:
    """Baseline C bloğunu okuyup kararı deterministik güçlendirir.

    Üretimde korelasyon ek kanıttır; mock bunu eşiği düşürme olarak
    modeler: hit_count >= 8 (veya seviye >= 12) → likely_malicious;
    hit_count >= 5 ve mevcut karar benign → suspicious. Blok yoksa
    karar değişmez (baseline B davranışı).
    """
    if CORR_BLOCK_MARKER not in user_prompt:
        return base
    try:
        marker_end = user_prompt.index(CORR_BLOCK_MARKER) + len(CORR_BLOCK_MARKER)
        block = user_prompt[marker_end:]
        start = block.index("[")
        end = block.rindex("]")
        detections = json.loads(block[start : end + 1])
    except (ValueError, IndexError):
        return base
    if not isinstance(detections, list):
        return base

    max_hits = max(
        (int(item.get("hit_count", 0)) for item in detections if isinstance(item, dict)),
        default=0,
    )
    if max_hits >= _CORR_MALICIOUS_MIN_HITS or level >= 12:
        return "likely_malicious"
    if max_hits >= _CORR_BUMP_SUSPICIOUS_MIN_HITS and base == "benign":
        return "suspicious"
    return base


__all__ = ["MockOllamaClient"]
