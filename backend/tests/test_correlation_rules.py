"""Korelasyon kural kataloğu testleri (Faz 06).

Katalog sözleşmesi: sürümlenmiş, doğrulanmış parametreler, benzersiz anahtar,
açıklanabilir basit kurallar (ML/anomali yok — phases/06 gereksinimi).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.services.correlation.rules import (
    CorrelationParams,
    CorrelationRuleDef,
    build_default_catalog,
    params_from_storage,
)

EXPECTED_KEYS = {
    "failed_login_burst",
    "repeated_alert",
    "suspicious_change_after_login",
}


class TestCatalogIntegrity:
    def test_catalog_has_expected_rules(self) -> None:
        catalog = build_default_catalog()
        assert {rule.key for rule in catalog} == EXPECTED_KEYS

    def test_catalog_keys_unique_and_sorted(self) -> None:
        catalog = build_default_catalog()
        keys = [rule.key for rule in catalog]
        assert len(keys) == len(set(keys))
        assert keys == sorted(keys)  # deterministik kural sırası

    def test_all_versions_at_least_one(self) -> None:
        for rule in build_default_catalog():
            assert rule.version >= 1
            assert rule.description.strip()
            assert rule.name.strip()

    def test_burst_rules_have_valid_thresholds(self) -> None:
        for rule in build_default_catalog():
            if rule.params.kind == "burst":
                assert rule.params.threshold >= 2
                assert rule.params.window_seconds > 0

    def test_sequence_rules_have_both_filters(self) -> None:
        for rule in build_default_catalog():
            if rule.params.kind == "sequence":
                assert rule.params.match_rule_ids or rule.params.match_rule_groups
                assert rule.params.then_rule_ids or rule.params.then_rule_groups

    def test_params_storage_roundtrip(self) -> None:
        rule = build_default_catalog()[0]
        stored = rule.params.to_storage()
        restored = params_from_storage(stored)
        assert restored == rule.params

    def test_params_from_storage_rejects_non_dict(self) -> None:
        with pytest.raises(ValueError, match="JSON nesnesi"):
            params_from_storage(["not", "a", "dict"])

    def test_params_from_storage_rejects_bad_payload(self) -> None:
        with pytest.raises(ValidationError):
            params_from_storage({"kind": "burst", "window_seconds": -5})


class TestParamsValidation:
    def test_sequence_requires_both_filters(self) -> None:
        with pytest.raises(ValidationError, match="sequence"):
            CorrelationParams(
                kind="sequence",
                window_seconds=600,
                group_by=["agent_id"],
                match_rule_groups=["authentication_success"],
                then_rule_ids=[],  # ikinci aşama boş → reddedilir
            )

    def test_sequence_filters_must_be_disjoint_ids(self) -> None:
        """Bulgu kapanışı (Faz 06 bağımsız doğrulama F2): çakışan filtreler
        sessiz 0-tespit tuzağı üretir → tanım başlangıçta reddedilir."""
        with pytest.raises(ValidationError, match="KESİŞMEMELİ"):
            CorrelationParams(
                kind="sequence",
                window_seconds=600,
                group_by=["agent_id"],
                match_rule_ids=["554"],
                match_rule_groups=["authentication_success"],
                then_rule_ids=["554"],  # aynı ID iki aşamada da
                then_rule_groups=["adduser"],
            )

    def test_sequence_filters_must_be_disjoint_groups(self) -> None:
        with pytest.raises(ValidationError, match="KESİŞMEMELİ"):
            CorrelationParams(
                kind="sequence",
                window_seconds=600,
                group_by=["agent_id"],
                match_rule_groups=["authentication_success", "adduser"],
                then_rule_groups=["adduser"],  # grup kesişimi
                then_rule_ids=["554"],
            )

    def test_catalog_sequence_rules_are_disjoint(self) -> None:
        """Kataloğun tüm sequence kuralları ayrıklık kısıtını sağlar."""
        for rule in build_default_catalog():
            if rule.params.kind == "sequence":
                assert not (
                    set(rule.params.match_rule_ids) & set(rule.params.then_rule_ids)
                )
                assert not (
                    set(rule.params.match_rule_groups)
                    & set(rule.params.then_rule_groups)
                )

    def test_group_by_cannot_be_empty(self) -> None:
        with pytest.raises(ValidationError):
            CorrelationParams(kind="burst", window_seconds=300, group_by=[])

    def test_group_by_rejects_unknown_field(self) -> None:
        with pytest.raises(ValidationError):
            CorrelationParams(
                kind="burst",
                window_seconds=300,
                group_by=["password_hash"],  # beyaz liste dışı alan
            )

    def test_window_upper_bound(self) -> None:
        with pytest.raises(ValidationError):
            CorrelationParams(
                kind="burst", window_seconds=86_401, group_by=["agent_id"]
            )

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            CorrelationParams(
                kind="burst",
                window_seconds=300,
                group_by=["agent_id"],
                ml_magic=True,  # bilinmeyen alan — sessiz kabul YOK
            )


class TestRuleDefValidation:
    def test_invalid_key_rejected(self) -> None:
        params = CorrelationParams(
            kind="burst", window_seconds=300, group_by=["agent_id"]
        )
        with pytest.raises(ValueError, match="anahtar"):
            CorrelationRuleDef(
                key="boşluk lu key!",  # noqa: S105 — geçersiz anahtar bilinçli
                name="x",
                description="y",
                version=1,
                params=params,
            )

    def test_invalid_version_rejected(self) -> None:
        params = CorrelationParams(
            kind="burst", window_seconds=300, group_by=["agent_id"]
        )
        with pytest.raises(ValueError, match="sürüm"):
            CorrelationRuleDef(
                key="ok_key", name="x", description="y", version=0, params=params
            )

    def test_key_too_long_rejected(self) -> None:
        params = CorrelationParams(
            kind="burst", window_seconds=300, group_by=["agent_id"]
        )
        with pytest.raises(ValueError):
            CorrelationRuleDef(
                key="a" * 65, name="x", description="y", version=1, params=params
            )
