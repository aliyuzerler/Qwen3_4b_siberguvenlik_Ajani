"""Müdahale kataloğu testleri (Faz 07).

Kapsam (phases/07): "Tipli action enum; serbest shell komutu yok",
"Allowlist, hedef kapsamı", "kritik erişimi kesebilecek firewall/SSH
işlemlerini varsayılan olarak engelle".

Bu testler KATALOĞUN kendini doğrular: allowlist üyeliği, tip param
şemalarının extra=forbid davranışı (command/args/shell reddi) ve
default_blocked bayrakları.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.services.remediation.catalog import (
    ACTION_BLOCK_SRC_IP,
    ACTION_ISOLATE_HOST,
    ACTION_LOCK_USER_ACCOUNT,
    ACTION_NOTIFY_ADMIN,
    ACTION_RESTART_WAZUH_AGENT,
    ALL_ACTION_TYPES,
    get_action_definition,
    list_action_definitions,
)
from app.services.remediation.executor import DryRunExecutor

pytestmark = pytest.mark.asyncio


class TestAllowlist:
    async def test_catalog_has_exactly_six_typed_actions(self) -> None:
        """Allowlist sabit: 6 tipli aksiyon; serbest komut tipi YOK."""
        definitions = list_action_definitions()
        assert len(definitions) == 6
        assert {d.key for d in definitions} == set(ALL_ACTION_TYPES)
        # Serbest shell komutu için bir aksiyon tipi TANIMLI DEĞİLDİR:
        for forbidden in ("run_command", "shell", "execute_command", "custom"):
            assert get_action_definition(forbidden) is None

    async def test_unknown_action_type_returns_none(self) -> None:
        """'modelden gelen serbest komut' katalogda yer ALAMAZ (allowlist)."""
        assert get_action_definition("rm -rf /tmp") is None
        assert get_action_definition("") is None

    async def test_firewall_ssh_account_actions_are_default_blocked(self) -> None:
        """Kritik erişimi kesebilecek işlemler VARSAYILAN ENGELLİ (phases/07)."""
        blocked_expected = {
            ACTION_BLOCK_SRC_IP,  # firewall
            ACTION_ISOLATE_HOST,  # ağ izolasyonu
            ACTION_LOCK_USER_ACCOUNT,  # SSH/hesap
        }
        for definition in list_action_definitions():
            if definition.key in blocked_expected:
                assert definition.default_blocked is True, definition.key
                assert definition.blocked_reason == "default_blocked"
                assert definition.blocked_detail  # açıklama zorunlu
            else:
                assert definition.default_blocked is False, definition.key

    async def test_every_definition_carries_risk_and_rollback_text(self) -> None:
        """'Eylem öncesi kanıt paketi ve risk açıklaması' → metinler zorunlu."""
        for definition in list_action_definitions():
            assert definition.risk_level in {"low", "medium", "high"}
            assert len(definition.risk_explanation) >= 20
            assert len(definition.rollback_note) >= 20
            assert len(definition.execution_plan) >= 20  # dry-run plan metni


class TestTypedParams:
    async def test_free_form_command_field_is_rejected(self) -> None:
        """Modelden gelse bile `command` alanı KABUL EDİLMEZ (extra=forbid)."""
        definition = get_action_definition(ACTION_RESTART_WAZUH_AGENT)
        assert definition is not None
        with pytest.raises(ValidationError):
            definition.validate_params({"agent_id": "001", "command": "rm -rf /"})
        with pytest.raises(ValidationError):
            definition.validate_params({"agent_id": "001", "args": ["-c", "id"]})
        with pytest.raises(ValidationError):
            definition.validate_params({"agent_id": "001", "shell": "/bin/sh"})

    async def test_agent_target_params(self) -> None:
        definition = get_action_definition(ACTION_RESTART_WAZUH_AGENT)
        assert definition is not None
        normalized = definition.validate_params({"agent_id": "001"})
        assert normalized == {"agent_id": "001"}
        with pytest.raises(ValidationError):
            definition.validate_params({})  # zorunlu alan yok
        with pytest.raises(ValidationError):
            definition.validate_params({"agent_id": "bad id with space"})

    async def test_block_src_ip_requires_valid_ip(self) -> None:
        definition = get_action_definition(ACTION_BLOCK_SRC_IP)
        assert definition is not None
        assert definition.validate_params({"ip": "203.0.113.7"}) == {
            "ip": "203.0.113.7"
        }
        with pytest.raises(ValidationError):
            definition.validate_params({"ip": "not-an-ip"})
        with pytest.raises(ValidationError):
            definition.validate_params({"ip": "203.0.113.7; rm -rf /"})

    async def test_lock_user_username_charset(self) -> None:
        definition = get_action_definition(ACTION_LOCK_USER_ACCOUNT)
        assert definition is not None
        assert definition.validate_params({"username": "svc-backup"}) == {
            "username": "svc-backup"
        }
        with pytest.raises(ValidationError):
            definition.validate_params({"username": "a"})  # çok kısa
        with pytest.raises(ValidationError):
            definition.validate_params({"username": "bad user!"})

    async def test_notify_admin_note_bound(self) -> None:
        definition = get_action_definition(ACTION_NOTIFY_ADMIN)
        assert definition is not None
        assert definition.validate_params({}) == {}
        assert definition.validate_params({"note": "kısa not"}) == {"note": "kısa not"}
        with pytest.raises(ValidationError):
            definition.validate_params({"note": "x" * 301})


class TestDryRunExecutor:
    async def test_dry_run_executor_is_only_implementation_and_simulates(self) -> None:
        """DryRunExecutor simülasyon döndürür; 'plan' metni katalogdan gelir."""
        executor = DryRunExecutor()
        definition = get_action_definition(ACTION_RESTART_WAZUH_AGENT)
        assert definition is not None
        result = await executor.execute(
            definition.key, {"agent_id": "001"}, {"event_ids": ["e1"]}
        )
        assert result.success is True
        assert result.simulated is True  # SİMÜLASYON etiketi daima true
        assert definition.execution_plan in result.output["plan"]
        assert result.output["mode"] == "dry_run"

    async def test_dry_run_executor_never_raises_on_unknown_type(self) -> None:
        executor = DryRunExecutor()
        result = await executor.execute("bilinmeyen", {}, {"event_ids": []})
        assert result.success is True
        assert result.simulated is True
        assert "Katalog dışı" in result.output["plan"]
