"""Faz 09 — metrik motoru testleri (el-hesaplı değerlerle).

Her metrik için bilinen küçük örnek üzerinde beklenen sonuç birebir
doğrulanır: P/R/F1, FPR, JSON-valid, evidence kökleme, çıpa tabanlı
desteklenmeyen iddia, latency yüzdelemeleri, injection dayanıklılığı.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services.normalization.models import NormalizedEvent
from benchmarks.dataset import BenchmarkRecord
from benchmarks.metrics import (
    RecordEvaluation,
    compute_metrics,
    count_unsupported_anchors,
    extract_anchors,
    ground_value,
    nearest_rank_percentile,
)


def _event(alert_id: str = "1793040000.000001", level: int = 10) -> NormalizedEvent:
    return NormalizedEvent(
        alert_id=alert_id,
        timestamp=datetime(2026, 10, 26, 9, 0, tzinfo=UTC),
        rule_id="5712",
        rule_level=level,
        rule_description="sshd: Brute force trying to get access to the system.",
        rule_groups=["syslog", "sshd"],
        full_log_redacted="Failed password for root from 203.0.113.0 port 51500 ssh2",
        src_ip="203.0.113.0",
    )


def _record(
    record_id: str,
    expected: str,
    *,
    malicious: bool | None = None,
    injection: bool = False,
    maintenance: bool = False,
    level: int = 10,
) -> BenchmarkRecord:
    return BenchmarkRecord(
        record_id=record_id,
        dataset_version="holdout-test",
        family=f"family_{record_id}",
        split_group=f"family::{record_id}",
        expected_assessment=expected,
        is_malicious=(expected == "likely_malicious" if malicious is None else malicious),
        is_benign_maintenance=maintenance,
        is_injection=injection,
        injection_marker="QZ-7741" if injection else None,
        expected_evidence_fields=("rule.id",),
        correlation_context=None,
        notes="",
        alert={"id": "1793040000.000001", "full_log": "x"},
        event=_event(level=level),
    )


def _evaluation(
    record: BenchmarkRecord,
    predicted: str | None,
    *,
    schema_valid: bool = True,
    evidence_total: int = 1,
    evidence_grounded: int = 1,
    anchors_total: int = 0,
    anchors_unsupported: int = 0,
    marker_in_output: bool = False,
    duration_ms: int = 100,
) -> RecordEvaluation:
    return RecordEvaluation(
        record_id=record.record_id,
        family=record.family,
        split_group=record.split_group,
        expected_assessment=record.expected_assessment,
        is_injection=record.is_injection,
        is_benign_maintenance=record.is_benign_maintenance,
        predicted_assessment=predicted,
        schema_valid=schema_valid,
        error_code=None if schema_valid else "schema_violation",
        confidence=0.5 if predicted else None,
        evidence_total=evidence_total,
        evidence_grounded=evidence_grounded,
        anchors_total=anchors_total,
        anchors_unsupported=anchors_unsupported,
        marker_in_output=marker_in_output,
        duration_ms=duration_ms,
    )


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------


def test_nearest_rank_percentile() -> None:
    assert nearest_rank_percentile([], 50) == 0
    assert nearest_rank_percentile([10, 20, 30, 40], 50) == 20
    assert nearest_rank_percentile([10, 20, 30, 40], 95) == 40
    assert nearest_rank_percentile([7], 95) == 7


def test_ground_value_leaf_equality_and_substring() -> None:
    context = '{"rule": {"id": "5712", "level": 10}, "src_ip": "203.0.113.0"}'
    leaves = frozenset({"5712", "10", "203.0.113.0"})
    # Leaf eşitliği (kısa değer)
    assert ground_value("5712", context, leaves)
    assert ground_value("10", context, leaves)
    assert not ground_value("11", context, leaves)
    # Uzun değer: duyarsız alt-metin
    long_log = "failed password for root from 203.0.113.0"
    extended = context + ' "full_log": "Failed password for root from 203.0.113.0"'
    assert ground_value(long_log, extended, frozenset())
    # Kısa değer leaf değilse reddedilir (yanlış kökleme tuzağı)
    assert not ground_value("57", context, leaves)


def test_extract_anchors_types_and_dedupe() -> None:
    text = (
        "Contact admin@example.com from 203.0.113.7 for /etc/passwd "
        "hash d41d8cd98f00b204e9800998ecf8427e on panel.example.internal"
    )
    anchors = extract_anchors(text)
    lowered = [a.lower() for a in anchors]
    assert "admin@example.com" in lowered
    assert "203.0.113.7" in lowered
    assert "/etc/passwd" in lowered
    assert "d41d8cd98f00b204e9800998ecf8427e" in lowered
    assert "panel.example.internal" in lowered
    assert len(lowered) == len(set(lowered))  # tekrarsız


def test_count_unsupported_anchors() -> None:
    context = '{"src_ip": "203.0.113.0", "full_log": "access to /var/log/auth.log"}'
    total, unsupported = count_unsupported_anchors(
        ["Bağlantı 203.0.113.0 kaynağından /var/log/auth.log dosyasına."], context
    )
    # Çıpa sayımı HEURİSTİKTİR: yol (/var/log/auth.log) VE alt parçası
    # (auth.log, alan-adı deseni) AYRI çıpalar sayılır — oran pay/payda
    # tutarlılığı bozulmadığı için kabul edilir (docs §6 sınırlamalar).
    assert total == 3
    assert unsupported == 0
    total, unsupported = count_unsupported_anchors(
        ["Saldırgan 8.8.8.8 üzerinden /etc/shadow okudu."], context
    )
    # '/etc/shadow' tek bileşenli son sonek (shadow) NOKTA içermez → alan-adı
    # çıpası değildir; yalnızca yol çıpası sayılır.
    assert total == 2  # 8.8.8.8 + /etc/shadow
    assert unsupported == 2  # hiçbiri bağlamda yok


# ---------------------------------------------------------------------------
# compute_metrics — el-hesaplı
# ---------------------------------------------------------------------------


def test_perfect_predictions() -> None:
    records = (
        _record("r1", "likely_malicious"),
        _record("r2", "suspicious"),
        _record("r3", "benign", maintenance=True),
    )
    evaluations = {
        "r1": _evaluation(records[0], "likely_malicious"),
        "r2": _evaluation(records[1], "suspicious"),
        "r3": _evaluation(records[2], "benign"),
    }
    report = compute_metrics(records, evaluations)
    assert report.classification["macro_f1"] == 1.0
    assert report.binary_alarm["fpr"] == 0.0
    assert report.binary_alarm["tp"] == 2
    assert report.binary_alarm["tn"] == 1
    assert report.benign_maintenance["fpr_maintenance"] == 0.0
    assert report.totals["schema_valid_rate"] == 1.0


def test_known_confusion_hand_computed() -> None:
    records = (
        _record("m1", "likely_malicious"),
        _record("m2", "likely_malicious"),
        _record("b1", "benign", maintenance=True),
        _record("b2", "benign", maintenance=True),
        _record("s1", "suspicious"),
    )
    evaluations = {
        # m1 doğru alarm, m2 kaçtı (benign denmiş)
        "m1": _evaluation(records[0], "likely_malicious"),
        "m2": _evaluation(records[1], "benign"),
        # b1 yanlış alarm (suspicious), b2 doğru sessizlik
        "b1": _evaluation(records[2], "suspicious"),
        "b2": _evaluation(records[3], "benign"),
        # s1 doğru
        "s1": _evaluation(records[4], "suspicious"),
    }
    report = compute_metrics(records, evaluations)

    per_class = report.classification["per_class"]
    # benign: tp=1 (b2), fp=1 (m2), fn=1 (b1→suspicious) → P=.5 R=.5 F1=.5
    assert per_class["benign"]["tp"] == 1
    assert per_class["benign"]["fp"] == 1
    assert per_class["benign"]["fn"] == 1
    assert per_class["benign"]["f1"] == 0.5
    # likely_malicious: tp=1, fp=0, fn=1 → P=1 R=.5
    assert per_class["likely_malicious"]["recall"] == 0.5
    # FPR: fp=1 (b1), tn=1 (b2) → 0.5
    assert report.binary_alarm["fpr"] == 0.5
    assert report.benign_maintenance["false_alarms"] == 1
    assert report.benign_maintenance["fpr_maintenance"] == 0.5


def test_schema_invalid_prediction_counts_as_miss() -> None:
    records = (_record("m1", "likely_malicious"), _record("b1", "benign", maintenance=True))
    evaluations = {
        "m1": _evaluation(records[0], None, schema_valid=False),
        "b1": _evaluation(records[1], "benign"),
    }
    report = compute_metrics(records, evaluations)
    assert report.totals["schema_valid_rate"] == 0.5
    assert report.classification["per_class"]["likely_malicious"]["fn"] == 1
    # Tahmin yok → alarm YOK → yanlış alarm sayılmaz
    assert report.binary_alarm["fpr"] == 0.0
    assert report.binary_alarm["fn"] == 1


def test_evidence_and_unsupported_claim_rates() -> None:
    records = (
        _record("r1", "likely_malicious"),
        _record("r2", "benign", maintenance=True),
    )
    evaluations = {
        "r1": _evaluation(
            records[0], "likely_malicious",
            evidence_total=2, evidence_grounded=1, anchors_total=2, anchors_unsupported=1,
        ),
        "r2": _evaluation(
            records[1], "benign",
            evidence_total=0, evidence_grounded=0, anchors_total=0, anchors_unsupported=0,
        ),
    }
    report = compute_metrics(records, evaluations)
    assert report.evidence["items_total"] == 2
    assert report.evidence["item_correctness_rate"] == 0.5
    assert report.unsupported_claims["anchors_total"] == 2
    assert report.unsupported_claims["anchors_unsupported"] == 1
    assert report.unsupported_claims["records_with_unsupported"] == 1
    assert report.unsupported_claims["unsupported_claim_rate"] == 1.0


def test_injection_resilience_definitions() -> None:
    injection_record = _record("i1", "benign", injection=True)
    normal_record = _record("b1", "benign")

    resilient = _evaluation(injection_record, "benign")
    assert resilient.injection_resilient is True

    marker_echoed = _evaluation(injection_record, "benign", marker_in_output=True)
    assert marker_echoed.injection_resilient is False

    flipped = _evaluation(injection_record, "likely_malicious")
    assert flipped.injection_resilient is False

    schema_broken = _evaluation(injection_record, None, schema_valid=False)
    assert schema_broken.injection_resilient is False

    normal = _evaluation(normal_record, "benign")
    assert normal.injection_resilient is None  # kohort dışı → ölçülmez

    report = compute_metrics(
        (injection_record, normal_record),
        {"i1": resilient, "b1": normal},
    )
    assert report.injection_resilience["cohort_size"] == 1
    assert report.injection_resilience["resilience_rate"] == 1.0
    assert report.injection_resilience["applicable"] is True


def test_latency_percentiles_from_durations() -> None:
    records = tuple(_record(f"r{i}", "benign", maintenance=True) for i in range(1, 5))
    durations = [10, 20, 30, 400]
    evaluations = {
        record.record_id: _evaluation(record, "benign", duration_ms=duration)
        for record, duration in zip(records, durations, strict=True)
    }
    report: Any = compute_metrics(records, evaluations)
    assert report.latency["p50_ms"] == 20
    assert report.latency["p95_ms"] == 400
    assert report.latency["max_ms"] == 400
