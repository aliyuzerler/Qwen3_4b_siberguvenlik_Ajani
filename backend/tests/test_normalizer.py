"""Normalizasyon testleri (Faz 03) — sentetik fixture'lar.

Kapsam (phases/03 test promptu): alan eksikliği, farklı timestamp biçimleri,
hassas alanlar, orijinal severity/rule korunumu, sürümlenmiş event modeli.

Gerçek müşteri verisi YOKTUR: tüm IP'ler RFC 5737/TEST-NET, alanlar örnektir.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from app.services.normalization.errors import NormalizationError
from app.services.normalization.models import EVENT_SCHEMA_VERSION, NormalizedEvent
from app.services.normalization.normalizer import normalize_alert
from app.services.normalization.redaction import MAX_FULL_LOG_CHARS, RedactionPolicy
from tests.conftest import make_alert

POLICY = RedactionPolicy()


class TestFieldMapping:
    def test_happy_path_maps_controlled_fields(self) -> None:
        event = normalize_alert(make_alert(), POLICY)
        assert event.source == "wazuh"
        assert event.alert_id == "1792974900.123456"  # orijinal ID korunur
        assert event.rule_id == "5712"
        assert event.rule_description.startswith("sshd: Brute force")
        assert event.rule_groups == ["syslog", "sshd"]
        assert event.agent_id == "001"
        assert event.agent_name == "web-server-01"
        assert event.manager == "wazuh-manager-01"
        assert event.location == "/var/log/auth.log"
        assert event.decoder == "sshd"

    def test_original_severity_preserved_as_int(self) -> None:
        # Kanonik severity daima ORİJİNAL rule_level int'tir; LLM üzerine yazamaz.
        for level in (0, 3, 7, 10, 15):
            event = normalize_alert(make_alert(rule_level=level), POLICY)
            assert event.rule_level == level

    def test_schema_version_is_set(self) -> None:
        event = normalize_alert(make_alert(), POLICY)
        assert event.schema_version == EVENT_SCHEMA_VERSION
        assert EVENT_SCHEMA_VERSION >= 1

    def test_model_assessment_not_in_event(self) -> None:
        # "Model değerlendirmesini ayrı alanda tut": event modelinde ai_assessment yok.
        assert "ai_assessment" not in NormalizedEvent.model_fields


class TestMissingFields:
    def test_empty_alert_id_rejected(self) -> None:
        with pytest.raises(NormalizationError):
            normalize_alert(make_alert(alert_id=""), POLICY)

    def test_empty_rule_id_rejected(self) -> None:
        with pytest.raises(NormalizationError):
            normalize_alert(make_alert(rule_id="  "), POLICY)

    def test_empty_rule_description_rejected(self) -> None:
        with pytest.raises(NormalizationError):
            normalize_alert(make_alert(rule_description=""), POLICY)

    def test_missing_optional_fields_stored_as_none(self) -> None:
        event = normalize_alert(
            make_alert(agent_id=None, agent_name=None, full_log=None, src_ip=None), POLICY
        )
        assert event.agent_id is None
        assert event.full_log_redacted is None
        assert event.src_ip is None


class TestTimestampFormats:
    def test_utc_z_suffix_normalized(self) -> None:
        alert = make_alert(timestamp=datetime(2026, 10, 26, 9, 15, 0, tzinfo=UTC))
        assert normalize_alert(alert, POLICY).timestamp.tzinfo == UTC

    def test_offset_timezone_converted_to_utc(self) -> None:
        istanbul = timezone(timedelta(hours=3))
        alert = make_alert(timestamp=datetime(2026, 10, 26, 12, 15, 0, tzinfo=istanbul))
        event = normalize_alert(alert, POLICY)
        assert event.timestamp == datetime(2026, 10, 26, 9, 15, 0, tzinfo=UTC)

    def test_naive_timestamp_assumed_utc(self) -> None:
        alert = make_alert(timestamp=datetime(2026, 10, 26, 9, 15, 0))  # tz'siz
        event = normalize_alert(alert, POLICY)
        assert event.timestamp.tzinfo == UTC
        assert event.timestamp.hour == 9


class TestRedactionInEvent:
    def test_secrets_masked_in_stored_context(self) -> None:
        alert = make_alert(
            full_log="login user=admin password=SuperSecret123 from 203.0.113.7",
            rule_description="Auth failure contact admin@example.com",
        )
        event = normalize_alert(alert, POLICY)
        assert event.full_log_redacted is not None
        assert "SuperSecret123" not in event.full_log_redacted
        assert "password=***" in event.full_log_redacted
        assert "admin@example.com" not in (event.rule_description or "")

    def test_src_ip_masked_by_policy(self) -> None:
        event = normalize_alert(make_alert(src_ip="203.0.113.7"), POLICY)
        assert event.src_ip == "203.0.113.0"  # masked (varsayılan)

    def test_full_log_truncated_to_limit(self) -> None:
        alert = make_alert(full_log="x" * (MAX_FULL_LOG_CHARS + 5000))
        event = normalize_alert(alert, POLICY)
        assert event.full_log_redacted is not None
        assert len(event.full_log_redacted) <= MAX_FULL_LOG_CHARS


class TestFingerprint:
    def test_fingerprint_deterministic(self) -> None:
        a = normalize_alert(make_alert(), POLICY)
        b = normalize_alert(make_alert(), POLICY)
        assert a.fingerprint == b.fingerprint
        assert len(a.fingerprint) == 64  # sha256 hex

    def test_fingerprint_changes_with_payload(self) -> None:
        # Faz 03 testi: "aynı ID ile değişik payload" ayırt edilebilmelidir.
        a = normalize_alert(make_alert(), POLICY)
        b = normalize_alert(make_alert(full_log="different content"), POLICY)
        assert a.fingerprint != b.fingerprint

    def test_fingerprint_changes_with_timestamp(self) -> None:
        a = normalize_alert(make_alert(), POLICY)
        b = normalize_alert(
            make_alert(timestamp=datetime(2026, 10, 26, 9, 15, 1, tzinfo=UTC)), POLICY
        )
        assert a.fingerprint != b.fingerprint

    def test_fingerprint_computed_over_masked_content(self) -> None:
        # Ham secret parmak izi girdisine girmez: farklı secret, aynı maske → aynı iz.
        a = normalize_alert(make_alert(full_log="password=SecretOne"), POLICY)
        b = normalize_alert(make_alert(full_log="password=SecretTwo"), POLICY)
        assert a.full_log_redacted == b.full_log_redacted
        assert a.fingerprint == b.fingerprint
