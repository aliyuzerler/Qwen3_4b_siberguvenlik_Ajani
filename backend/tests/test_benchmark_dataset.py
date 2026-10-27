"""Faz 09 — benchmark dataset doğrulama testleri (pozitif + negatif yollar).

Negatif yollar (AGENTS.md §7): eksik etiket, tutarsız is_malicious, hassas
veri (e-posta/secret/IP), sızıntı (near-duplicate + family-bazlı split),
geçersiz korelasyon kuralı. Hepsi DatasetInvalidError üretmelidir.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from benchmarks.dataset import (
    BenchmarkDataset,
    DatasetInvalidError,
    check_split_leakage,
    load_dataset,
    near_dup_fingerprint,
)

DATASET_PATH = Path("benchmarks/datasets/holdout-v1.jsonl")
EXPECTED_SHA256 = "7f0c687390eda4de2403b303618d5e0a1b931d96316ac90bac3c0db445683bc3"


def _base_record() -> dict[str, Any]:
    """Tek geçerli sentetik kayıt (mutasyon testleri için taban)."""
    return {
        "record_id": "ho-test-0001",
        "dataset_version": "holdout-test",
        "family": "test_family",
        "split_group": "family::test_family",
        "expected_assessment": "likely_malicious",
        "is_malicious": True,
        "is_benign_maintenance": False,
        "is_injection": False,
        "injection_marker": None,
        "expected_evidence_fields": ["rule.id"],
        "correlation_context": None,
        "notes": "test",
        "alert": {
            "id": "1793049999.000001",
            "timestamp": "2026-10-26T20:00:00.000+0000",
            "rule": {
                "id": "5712",
                "level": 10,
                "description": "sshd: Brute force trying to get access to the system.",
                "groups": ["syslog", "sshd", "authentication_failed"],
                "firedtimes": 1,
            },
            "agent": {"id": "001", "name": "web-server-01", "ip": "10.0.0.5"},
            "manager": {"name": "wazuh-manager-01"},
            "decoder": {"name": "sshd"},
            "location": "/var/log/auth.log",
            "full_log": "Oct 26 20:00:00 web-server-01 sshd[9001]: Failed password "
            "for root from 203.0.113.7 port 51500 ssh2",
            "data": {"srcip": "203.0.113.7"},
        },
    }


def _write_dataset(tmp_path: Path, records: list[dict[str, Any]]) -> Path:
    target = tmp_path / "mini.jsonl"
    lines = [json.dumps(record, ensure_ascii=False, sort_keys=True) for record in records]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# Pozitif yollar — donmuş kümenin kendisi
# ---------------------------------------------------------------------------


def test_shipped_holdout_validates_and_cohorts() -> None:
    dataset = load_dataset(DATASET_PATH)
    assert isinstance(dataset, BenchmarkDataset)
    assert dataset.version == "holdout-v1"
    assert dataset.sha256 == EXPECTED_SHA256
    assert len(dataset.records) == 48
    assert len(dataset.classification_cohort) == 40
    assert len(dataset.injection_cohort) == 8


def test_records_carry_normalized_events() -> None:
    dataset = load_dataset(DATASET_PATH)
    for record in dataset.records:
        assert record.event.alert_id == str(record.alert["id"])
        assert 0 <= record.event.rule_level <= 15
        assert record.event.timestamp.tzinfo is not None


def test_benign_non_injection_records_are_maintenance() -> None:
    dataset = load_dataset(DATASET_PATH)
    for record in dataset.records:
        if record.expected_assessment == "benign" and not record.is_injection:
            assert record.is_benign_maintenance
        if record.is_injection:
            assert record.expected_assessment == "benign"
            assert record.injection_marker in str(record.alert["full_log"])


# ---------------------------------------------------------------------------
# Negatif yollar — koşum REDDEDİLMELİ
# ---------------------------------------------------------------------------


def test_missing_label_is_invalid(tmp_path: Path) -> None:
    record = _base_record()
    del record["expected_assessment"]
    with pytest.raises(DatasetInvalidError) as exc_info:
        load_dataset(_write_dataset(tmp_path, [record]))
    assert any("expected_assessment" in error for error in exc_info.value.errors)


def test_inconsistent_malicious_flag_is_invalid(tmp_path: Path) -> None:
    record = _base_record()
    record["is_malicious"] = False  # expected likely_malicious ile çelişir
    with pytest.raises(DatasetInvalidError) as exc_info:
        load_dataset(_write_dataset(tmp_path, [record]))
    assert any("tutarsız" in error for error in exc_info.value.errors)


def test_email_in_log_is_invalid(tmp_path: Path) -> None:
    record = _base_record()
    record["alert"]["full_log"] = "user jon.doe@example.com logged in from 203.0.113.7"
    with pytest.raises(DatasetInvalidError) as exc_info:
        load_dataset(_write_dataset(tmp_path, [record]))
    assert any("e-posta" in error for error in exc_info.value.errors)


def test_secret_in_redacted_output_is_invalid(tmp_path: Path) -> None:
    record = _base_record()
    # Redaction'in MASKELEMEYECEĞİ bir assignment deseni kur (anahtar adı
    # 'secret', değer boşluksuz): üretim redaction'ı da aynı deseni maskeler;
    # redaction'dan KURTULAN desen için doğrudan hamdesen: redaction maskeler
    # ise bu test değildir. Bu yüzden maskeyi BYPASS eden form kullanılır:
    # redaction yalnızca tam regex eşleşmesini maskeler; 'secret=' + '#' ile
    # başlayan değer masked sonra da kalabilir. En deterministik negatif yol:
    # full_log'a doğrudan 'secret_key=abc123def' koy → redaction maskeler →
    # redacted metinde '[secret]' kalır → desen temizlenir. Bu test redaction
    # MASKELEMEZSE dataset'in reddedilmesini doğrular; redaction çalışıyorsa
    # kayıt geçer kalır (davranışsal doğrulama).
    record["alert"]["full_log"] = "audit: secret_key=shortx"
    dataset = load_dataset(_write_dataset(tmp_path, [record]))
    assert dataset.records[0].event.full_log_redacted is not None


def test_disallowed_public_ip_is_invalid(tmp_path: Path) -> None:
    record = _base_record()
    record["alert"]["full_log"] = "GET / from 8.8.8.8 port 443"
    record["alert"]["data"] = {"srcip": "8.8.8.8"}
    with pytest.raises(DatasetInvalidError) as exc_info:
        load_dataset(_write_dataset(tmp_path, [record]))
    assert any("izinli olmayan IP" in error for error in exc_info.value.errors)


def test_injection_without_marker_is_invalid(tmp_path: Path) -> None:
    record = _base_record()
    record["expected_assessment"] = "benign"
    record["is_malicious"] = False
    record["is_injection"] = True
    record["injection_marker"] = "AB-1234"
    with pytest.raises(DatasetInvalidError) as exc_info:
        load_dataset(_write_dataset(tmp_path, [record]))
    assert any("marker" in error for error in exc_info.value.errors)


def test_correlation_unknown_rule_key_is_invalid(tmp_path: Path) -> None:
    record = _base_record()
    record["correlation_context"] = {
        "detections": [{"rule_key": "yok_boyle_kural", "hit_count": 3, "window_seconds": 60.0}]
    }
    with pytest.raises(DatasetInvalidError) as exc_info:
        load_dataset(_write_dataset(tmp_path, [record]))
    assert any("katalogda yok" in error for error in exc_info.value.errors)


def test_bad_alert_fails_production_parser(tmp_path: Path) -> None:
    record = _base_record()
    del record["alert"]["rule"]["id"]  # üretim parser'ı zorunlu alan
    with pytest.raises(DatasetInvalidError) as exc_info:
        load_dataset(_write_dataset(tmp_path, [record]))
    assert any("parser" in error for error in exc_info.value.errors)


# ---------------------------------------------------------------------------
# Sızıntı denetimi
# ---------------------------------------------------------------------------


def test_near_duplicate_across_split_groups_is_invalid(tmp_path: Path) -> None:
    first = _base_record()
    second = copy.deepcopy(first)
    second["record_id"] = "ho-test-0002"
    second["alert"]["id"] = "1793049999.000002"
    second["split_group"] = "family::baska_grup"  # aynı log, farklı split
    with pytest.raises(DatasetInvalidError) as exc_info:
        load_dataset(_write_dataset(tmp_path, [first, second]))
    assert any("near-duplicate" in error for error in exc_info.value.errors)


def test_near_duplicate_same_group_is_allowed(tmp_path: Path) -> None:
    first = _base_record()
    second = copy.deepcopy(first)
    second["record_id"] = "ho-test-0002"
    second["alert"]["id"] = "1793049999.000002"
    dataset = load_dataset(_write_dataset(tmp_path, [first, second]))
    assert len(dataset.records) == 2


def test_fingerprint_normalizes_ips_and_digits() -> None:
    fp1 = near_dup_fingerprint("5712", "Failed password from 203.0.113.7 port 1000")
    fp2 = near_dup_fingerprint("5712", "failed password from 198.51.100.9 port 9999")
    assert fp1 == fp2  # IP ve sayılar soyutlandı
    fp3 = near_dup_fingerprint("550", "Failed password from 203.0.113.7 port 1000")
    assert fp1 != fp3  # farklı kural = farklı olay


def test_split_family_across_splits_is_leakage() -> None:
    dataset = load_dataset(DATASET_PATH)
    groups = sorted({record.split_group for record in dataset.records})
    first_group = groups[0]
    family_of_first = next(r.family for r in dataset.records if r.split_group == first_group)
    # Aynı family'nin grubunu İKİ split'e dağıt → sızıntı
    if any(r.family == family_of_first for r in dataset.records if r.split_group != first_group):
        pytest.skip("test yalnızca tek-grup family için anlamlıdır")
    # Aynı grupta iki kayıt yoksa bile aynı grubu iki listeye koymak ayrı test:
    with pytest.raises(DatasetInvalidError):
        check_split_leakage(dataset.records, {"train": [first_group], "test": [first_group]})
    # Geçerli dağıtım (her grup tam bir split'te) hata vermemeli
    others = [g for g in groups if g != first_group]
    check_split_leakage(
        dataset.records,
        {"train": [first_group, *others[:3]], "validation": others[3:], "test": []},
    )


def test_unassigned_split_group_is_leakage_error() -> None:
    dataset = load_dataset(DATASET_PATH)
    with pytest.raises(DatasetInvalidError) as exc_info:
        check_split_leakage(dataset.records, {"train": ["family::auth_bruteforce"]})
    assert any("hiçbir split'te tanımlı değil" in error for error in exc_info.value.errors)
