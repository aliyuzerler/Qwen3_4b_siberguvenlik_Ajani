"""ModelAnalysis katı şema doğrulama testleri (Faz 04 kabul).

Fixture matrisi (phases/04 doğrulama promptu): geçerli JSON, eksik alan,
ekstra alan, yanlış enum, confidence aralık dışı, çok uzun çıktı,
serbest komut önerisi reddi.
"""

from __future__ import annotations

import json

import pytest

from app.services.analysis.errors import (
    OUTPUT_ERROR_INVALID_JSON,
    OUTPUT_ERROR_SCHEMA_VIOLATION,
    OUTPUT_ERROR_TOO_LONG,
    AnalysisOutputError,
)
from app.services.analysis.models import (
    ANALYSIS_SCHEMA_VERSION,
    Assessment,
    ModelAnalysis,
    RecommendedStep,
    parse_model_analysis,
)
from tests.conftest import make_valid_model_output


def _payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = json.loads(make_valid_model_output())
    payload.update(overrides)
    return payload


def _validate(**overrides: object) -> ModelAnalysis:
    return ModelAnalysis.model_validate(_payload(**overrides))


class TestValidOutput:
    def test_valid_output_parses(self) -> None:
        analysis = _validate()
        assert analysis.schema_version == ANALYSIS_SCHEMA_VERSION == 1
        assert analysis.assessment is Assessment.SUSPICIOUS
        assert analysis.confidence == 0.7
        assert analysis.evidence[0].field == "rule.description"
        assert analysis.recommended_next_steps[0] is RecommendedStep.REVIEW_FULL_LOGS
        assert analysis.requires_human_review is True

    def test_parse_model_analysis_roundtrip(self) -> None:
        raw = make_valid_model_output(alert_id="123.456")
        analysis = parse_model_analysis(raw, max_chars=6000)
        assert analysis.alert_ids == ["123.456"]

    def test_scalar_evidence_coerced_to_str(self) -> None:
        analysis = _validate(
            evidence=[{"field": "dst_port", "value": 22}, {"field": "is_tls", "value": False}]
        )
        assert analysis.evidence[0].value == "22"
        assert analysis.evidence[1].value == "false"


class TestMissingFields:
    @pytest.mark.parametrize(
        ("missing_field", "expected_loc"),
        [
            ("schema_version", "schema_version"),
            ("alert_ids", "alert_ids"),
            ("summary", "summary"),
            ("assessment", "assessment"),
            ("confidence", "confidence"),
            ("evidence", "evidence"),
            ("requires_human_review", "requires_human_review"),
        ],
    )
    def test_missing_required_field_rejected(
        self, missing_field: str, expected_loc: str
    ) -> None:
        payload = _payload()
        payload.pop(missing_field)
        with pytest.raises(AnalysisOutputError) as exc:
            parse_model_analysis(json.dumps(payload), max_chars=6000)
        assert exc.value.error_code == OUTPUT_ERROR_SCHEMA_VIOLATION
        assert expected_loc in str(exc.value)


class TestExtraFields:
    def test_extra_field_rejected(self) -> None:
        """extra=forbid: modelin uydurduğu alan (örn. severity) REDDEDİLİR."""
        with pytest.raises(AnalysisOutputError) as exc:
            parse_model_analysis(
                json.dumps(_payload(severity="critical", unauthorized_field=1)),
                max_chars=6000,
            )
        assert exc.value.error_code == OUTPUT_ERROR_SCHEMA_VIOLATION

    def test_model_cannot_produce_severity_field(self) -> None:
        """AGENTS.md §5: çıktıda severity alanı olsa bile şema reddeder —
        orijinal Wazuh severity üzerine yazılma yolu TİP düzeyinde yoktur."""
        with pytest.raises(AnalysisOutputError):
            parse_model_analysis(
                json.dumps(_payload(rule_level=0, severity="benign")), max_chars=6000
            )


class TestEnums:
    @pytest.mark.parametrize("bad_value", ["malicious", "BENIGN", "hack", ""])
    def test_wrong_assessment_enum_rejected(self, bad_value: str) -> None:
        with pytest.raises(AnalysisOutputError) as exc:
            parse_model_analysis(
                json.dumps(_payload(assessment=bad_value)), max_chars=6000
            )
        assert exc.value.error_code == OUTPUT_ERROR_SCHEMA_VIOLATION

    def test_wrong_step_enum_rejected_with_free_command(self) -> None:
        """Serbest komut ('rm -rf /') öneri türü DEĞİLDİR → REDDEDİLİR."""
        with pytest.raises(AnalysisOutputError) as exc:
            parse_model_analysis(
                json.dumps(_payload(recommended_next_steps=["rm -rf /"])),
                max_chars=6000,
            )
        assert exc.value.error_code == OUTPUT_ERROR_SCHEMA_VIOLATION

    @pytest.mark.parametrize(
        "step",
        [
            "review_full_logs",
            "correlate_related_events",
            "check_agent_health",
            "verify_asset_criticality",
            "escalate_to_human_analyst",
            "update_detection_content",
            "none",
        ],
    )
    def test_all_whitelisted_steps_accepted(self, step: str) -> None:
        analysis = _validate(recommended_next_steps=[step])
        assert analysis.recommended_next_steps[0].value == step


class TestConfidence:
    @pytest.mark.parametrize("bad", [1.5, -0.1, 2, 100, "yüksek"])
    def test_confidence_out_of_range_rejected(self, bad: object) -> None:
        with pytest.raises(AnalysisOutputError) as exc:
            parse_model_analysis(json.dumps(_payload(confidence=bad)), max_chars=6000)
        assert exc.value.error_code == OUTPUT_ERROR_SCHEMA_VIOLATION

    @pytest.mark.parametrize("ok", [0.0, 1.0, 0.35, 0])
    def test_confidence_bounds_accepted(self, ok: float) -> None:
        analysis = _validate(confidence=ok)
        assert 0.0 <= analysis.confidence <= 1.0


class TestTooLongOutput:
    def test_raw_output_over_limit_rejected_before_parse(self) -> None:
        raw = make_valid_model_output(summary="x" * 100)
        with pytest.raises(AnalysisOutputError) as exc:
            parse_model_analysis(raw, max_chars=50)
        assert exc.value.error_code == OUTPUT_ERROR_TOO_LONG

    def test_over_long_summary_rejected(self) -> None:
        with pytest.raises(AnalysisOutputError) as exc:
            parse_model_analysis(
                json.dumps(_payload(summary="a" * 2001)), max_chars=6000
            )
        assert exc.value.error_code == OUTPUT_ERROR_SCHEMA_VIOLATION

    def test_too_many_evidence_items_rejected(self) -> None:
        evidence = [{"field": f"f{i}", "value": "v"} for i in range(11)]
        with pytest.raises(AnalysisOutputError):
            parse_model_analysis(json.dumps(_payload(evidence=evidence)), max_chars=6000)


class TestInvalidJson:
    def test_non_json_text_rejected(self) -> None:
        with pytest.raises(AnalysisOutputError) as exc:
            parse_model_analysis("bu bir JSON değil", max_chars=6000)
        assert exc.value.error_code == OUTPUT_ERROR_INVALID_JSON

    def test_json_array_rejected(self) -> None:
        with pytest.raises(AnalysisOutputError) as exc:
            parse_model_analysis("[]", max_chars=6000)
        assert exc.value.error_code == OUTPUT_ERROR_SCHEMA_VIOLATION

    def test_json_scalar_rejected(self) -> None:
        with pytest.raises(AnalysisOutputError) as exc:
            parse_model_analysis("42", max_chars=6000)
        assert exc.value.error_code == OUTPUT_ERROR_SCHEMA_VIOLATION

    def test_broken_replacement_chars_rejected(self) -> None:
        """Bozuk UTF-8 decode sonucu replacement karakterli metin → invalid_json."""
        with pytest.raises(AnalysisOutputError) as exc:
            parse_model_analysis('{"summary": "\ufffd\ufffd\ufffd"', max_chars=6000)
        assert exc.value.error_code == OUTPUT_ERROR_INVALID_JSON


class TestTraceabilityAndMisc:
    def test_empty_alert_ids_rejected(self) -> None:
        with pytest.raises(AnalysisOutputError):
            parse_model_analysis(json.dumps(_payload(alert_ids=[])), max_chars=6000)

    def test_inconclusive_assessment_valid(self) -> None:
        analysis = _validate(assessment="inconclusive", confidence=0.2)
        assert analysis.assessment is Assessment.INCONCLUSIVE

    def test_error_message_is_structural_not_content(self) -> None:
        """Hata mesajı yapısal bilgi taşır; model çıktı içeriği ham haliyle sızmaz."""
        with pytest.raises(AnalysisOutputError) as exc:
            parse_model_analysis(
                json.dumps(_payload(summary="SECRET-CONTENT " + "x" * 3000)),
                max_chars=6000,
            )
        assert "SECRET-CONTENT" not in exc.value.message
