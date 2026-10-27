"""Faz 09 — baseline testleri (rules_only determinizmi + LLM yolları).

Kapsam: eşik haritası, izlenebilirlik zoru, korelasyon bloğu kurulumu,
mock istemci yolu (B ve C), çıktı-hatası ve izlenebilirlik-ihlali
negatif yolları, altyapı-hatası fail-fast.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.analysis.errors import OUTPUT_ERROR_SCHEMA_VIOLATION, OllamaUnavailableError
from benchmarks.baselines import (
    CORR_BLOCK_MARKER,
    LlmBaseline,
    RulesOnlyBaseline,
    build_correlation_block,
    context_from_record,
    rules_assessment,
)
from benchmarks.dataset import load_dataset
from benchmarks.mock_client import MockOllamaClient

DATASET_PATH = "benchmarks/datasets/holdout-v1.jsonl"


@pytest.fixture()
def dataset() -> Any:
    return load_dataset(__import__("pathlib").Path(DATASET_PATH))


def _record_by_id(dataset: Any, record_id: str) -> Any:
    for record in dataset.records:
        if record.record_id == record_id:
            return record
    raise AssertionError(f"kayıt yok: {record_id}")


# ---------------------------------------------------------------------------
# rules_only
# ---------------------------------------------------------------------------


def test_rules_threshold_mapping() -> None:
    assert rules_assessment(15) == "likely_malicious"
    assert rules_assessment(12) == "likely_malicious"
    assert rules_assessment(11) == "suspicious"
    assert rules_assessment(7) == "suspicious"
    assert rules_assessment(6) == "benign"
    assert rules_assessment(0) == "benign"


async def test_rules_only_produces_contract_output(dataset: Any) -> None:
    record = _record_by_id(dataset, "ho-v1-0010")  # L12 encoded PowerShell
    prediction = await RulesOnlyBaseline().predict(record)

    assert prediction.schema_valid is True
    assert prediction.analysis is not None
    analysis = prediction.analysis
    assert analysis.assessment == "likely_malicious"
    assert analysis.alert_ids == [record.event.alert_id]  # izlenebilirlik
    assert {"field": "rule.id", "value": record.event.rule_id} in [
        {"field": item.field, "value": item.value} for item in analysis.evidence
    ]
    assert analysis.requires_human_review is True


async def test_rules_only_level10_maps_to_suspicious(dataset: Any) -> None:
    # Eşik haritası: 7-11 → suspicious. L10 brute-force kuralı ikili alarm
    # görünümünde alarmdır ama 3-sınıf etiketiyle (likely_malicious) farkı
    # baseline'ın kabalığını gösterir — ölçümün amacı budur.
    record = _record_by_id(dataset, "ho-v1-0001")
    prediction = await RulesOnlyBaseline().predict(record)
    assert prediction.analysis is not None
    assert prediction.analysis.assessment == "suspicious"
    assert prediction.analysis.requires_human_review is True


async def test_rules_only_benign_record(dataset: Any) -> None:
    record = _record_by_id(dataset, "ho-v1-0027")  # backup L3
    prediction = await RulesOnlyBaseline().predict(record)
    assert prediction.analysis is not None
    assert prediction.analysis.assessment == "benign"
    assert prediction.analysis.requires_human_review is False


# ---------------------------------------------------------------------------
# Korelasyon bloğu (baseline C)
# ---------------------------------------------------------------------------


def test_correlation_block_contains_detections(dataset: Any) -> None:
    record = _record_by_id(dataset, "ho-v1-0002")  # failed_login_burst hit 9
    block = build_correlation_block(record)
    assert CORR_BLOCK_MARKER in block
    assert "failed_login_burst" in block
    assert '"hit_count": 9' in block


def test_correlation_block_empty_for_plain_records(dataset: Any) -> None:
    record = _record_by_id(dataset, "ho-v1-0001")
    block = build_correlation_block(record)
    assert "[]" in block  # detections boş


def test_context_mapping_matches_production_fields(dataset: Any) -> None:
    record = _record_by_id(dataset, "ho-v1-0001")
    context = context_from_record(record)
    assert context.event_id == record.record_id
    assert context.alert_id == record.event.alert_id
    assert context.rule_level == record.event.rule_level
    assert context.full_log_redacted == record.event.full_log_redacted


# ---------------------------------------------------------------------------
# LlmBaseline + MockOllamaClient (hat doğrulaması)
# ---------------------------------------------------------------------------


def _llm_baseline(client: Any, *, include_correlation: bool) -> LlmBaseline:
    return LlmBaseline(
        client,
        include_correlation=include_correlation,
        model_tag="qwen3:4b",
        temperature=0.2,
        num_predict=512,
        timeout_seconds=5.0,
        max_context_chars=4000,
        max_output_chars=6000,
    )


async def test_mock_baseline_b_path(dataset: Any) -> None:
    record = _record_by_id(dataset, "ho-v1-0010")  # L12 → mock eşik: likely_malicious
    prediction = await _llm_baseline(MockOllamaClient(), include_correlation=False).predict(record)

    assert prediction.schema_valid is True
    assert prediction.analysis is not None
    assert prediction.analysis.alert_ids == [record.event.alert_id]
    assert prediction.analysis.assessment == "likely_malicious"
    # Prompt'ta korelasyon bloğu YOK (B davranışı)
    assert CORR_BLOCK_MARKER not in (prediction.raw_output or "")
    # Kanıt köklü: mock yalnızca bağlam alanlarından seçer
    for item in prediction.analysis.evidence:
        assert item.value in (record.event.rule_id, record.event.src_ip or "")


async def test_mock_baseline_c_path_strengthens_with_correlation(dataset: Any) -> None:
    # ho-v1-0028: backup_job L3 benign + repeated_alert hit 6 → mock suspicious'e yükseltir
    record = _record_by_id(dataset, "ho-v1-0028")
    prediction = await _llm_baseline(MockOllamaClient(), include_correlation=True).predict(record)

    assert prediction.schema_valid is True
    assert prediction.analysis is not None
    assert prediction.analysis.assessment == "suspicious"


async def test_mock_baseline_c_without_bump_stays_benign(dataset: Any) -> None:
    # ho-v1-0027: backup L3, korelasyon YOK → benign kalır
    record = _record_by_id(dataset, "ho-v1-0027")
    prediction = await _llm_baseline(MockOllamaClient(), include_correlation=True).predict(record)
    assert prediction.analysis is not None
    assert prediction.analysis.assessment == "benign"


class _GarbageClient:
    """Geçersiz JSON döndüren sözleşme-dışı istemci (negatif yol)."""

    async def generate(self, **kwargs: Any) -> str:
        del kwargs
        return "bu bir JSON değildir {"

    async def check_health(self) -> None:
        return None

    async def ensure_model(self, model_tag: str) -> None:
        del model_tag

    async def aclose(self) -> None:
        return None


class _WrongAlertIdClient:
    """Geçerli şema ama yanlış alert_ids (izlenebilirlik ihlali)."""

    async def generate(self, **kwargs: Any) -> str:
        del kwargs
        return (
            '{"schema_version": 1, "alert_ids": ["baska-alert"], '
            '"summary": "x", "assessment": "benign", "confidence": 0.5, '
            '"evidence": [], "alternative_explanations": [], '
            '"recommended_next_steps": ["none"], "requires_human_review": false}'
        )

    async def check_health(self) -> None:
        return None

    async def ensure_model(self, model_tag: str) -> None:
        del model_tag

    async def aclose(self) -> None:
        return None


class _UnreachableClient:
    """Altyapı hatası üreten istemci (fail-fast yolu)."""

    async def generate(self, **kwargs: Any) -> str:
        del kwargs
        raise OllamaUnavailableError("bağlantı yok (test)")

    async def check_health(self) -> None:
        return None

    async def ensure_model(self, model_tag: str) -> None:
        del model_tag

    async def aclose(self) -> None:
        return None


async def test_invalid_json_output_is_schema_invalid(dataset: Any) -> None:
    record = _record_by_id(dataset, "ho-v1-0001")
    prediction = await _llm_baseline(_GarbageClient(), include_correlation=False).predict(record)
    assert prediction.schema_valid is False
    assert prediction.analysis is None
    assert prediction.error_code == "invalid_json"


async def test_traceability_violation_is_schema_invalid(dataset: Any) -> None:
    record = _record_by_id(dataset, "ho-v1-0001")
    prediction = await _llm_baseline(
        _WrongAlertIdClient(), include_correlation=False
    ).predict(record)
    assert prediction.schema_valid is False
    assert prediction.error_code == OUTPUT_ERROR_SCHEMA_VIOLATION


async def test_infrastructure_error_propagates_fail_fast(dataset: Any) -> None:
    record = _record_by_id(dataset, "ho-v1-0001")
    with pytest.raises(OllamaUnavailableError):
        await _llm_baseline(_UnreachableClient(), include_correlation=False).predict(record)
