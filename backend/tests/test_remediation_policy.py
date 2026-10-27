"""Politika motoru testleri (Faz 07).

Kapsam (phases/07 test promptu): "modelden gelen serbest komut, bilinmeyen
action type, yanlış hedef, ... kritik erişimi kesebilecek eylemlerin
reddedildiğini doğrula" — motor düzeyinde birim testler (determinizm).

Not: kanıt paketi yapısı servis tarafından üretilir; burada sentetik kanıt
sözlükleri kullanılır (alan adları servis sözleşmesiyle aynıdır).
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.remediation.catalog import (
    ACTION_BLOCK_SRC_IP,
    ACTION_ISOLATE_HOST,
    ACTION_NOTIFY_ADMIN,
    ACTION_RESTART_WAZUH_AGENT,
)
from app.services.remediation.errors import (
    DefaultBlockedError,
    InvalidParamsError,
    ModeBlockedError,
    TargetScopeError,
    UnknownActionTypeError,
)
from app.services.remediation.policy import (
    POLICY_MODE_DRY_RUN,
    POLICY_MODE_OBSERVE_ONLY,
    evaluate_proposal,
    revalidate_for_execution,
)

pytestmark = pytest.mark.asyncio


def make_evidence(**overrides: Any) -> dict[str, Any]:
    """Sentetik kanıt paketi (servis build_evidence çıktısıyla aynı alanlar)."""
    base: dict[str, Any] = {
        "event_ids": ["11111111-1111-1111-1111-111111111111"],
        "alert_ids": ["100.1"],
        "rule_ids": ["5712"],
        "agent_ids": ["001"],
        "agent_names": ["web-server-01"],
        "src_ips": ["203.0.113.7"],
        "max_rule_level": 10,
        "window_start": "2026-10-27T09:00:00+00:00",
        "window_end": "2026-10-27T09:05:00+00:00",
        "correlation_id": None,
        "risk_level": "medium",
        "risk_explanation": "sentetik risk metni",
        "rollback_note": "sentetik rollback metni",
        "policy_mode": "dry_run",
        "built_at": "2026-10-27T09:06:00+00:00",
    }
    base.update(overrides)
    return base


class TestAllowlistGate:
    async def test_unknown_action_type_rejected(self) -> None:
        with pytest.raises(UnknownActionTypeError) as excinfo:
            evaluate_proposal(
                "run_shell_command", {}, make_evidence(),
                action_enabled=True, allow_blocked_actions=False,
            )
        assert "allowlist" in str(excinfo.value.message).lower()

    async def test_free_command_via_params_rejected_as_invalid(self) -> None:
        """Serbest komut: tip geçerli ama params'ta command alanı → params_valid RED."""
        with pytest.raises(InvalidParamsError):
            evaluate_proposal(
                ACTION_RESTART_WAZUH_AGENT,
                {"agent_id": "001", "command": "cat /etc/shadow"},
                make_evidence(),
                action_enabled=True,
                allow_blocked_actions=False,
            )

    async def test_disabled_action_rejected(self) -> None:
        with pytest.raises(Exception) as excinfo:  # PolicyBlockedError(reason=action_disabled)
            evaluate_proposal(
                ACTION_RESTART_WAZUH_AGENT,
                {"agent_id": "001"},
                make_evidence(),
                action_enabled=False,
                allow_blocked_actions=False,
            )
        assert getattr(excinfo.value, "reason", "") == "action_disabled"


class TestDefaultBlockedGate:
    async def test_firewall_action_denied_without_global_flag(self) -> None:
        """Firewall aksiyonu: operatör enable olsa bile global kapı kapalıyken RED."""
        with pytest.raises(DefaultBlockedError):
            evaluate_proposal(
                ACTION_BLOCK_SRC_IP,
                {"ip": "203.0.113.7"},
                make_evidence(),
                action_enabled=True,
                allow_blocked_actions=False,
            )

    async def test_default_blocked_disabled_operator_denied_first(self) -> None:
        """Varsayılan durum: DB'de enabled=false (ilk kapı) → action_disabled RED."""
        with pytest.raises(Exception) as excinfo:
            evaluate_proposal(
                ACTION_BLOCK_SRC_IP,
                {"ip": "203.0.113.7"},
                make_evidence(),
                action_enabled=False,
                allow_blocked_actions=False,
            )
        assert getattr(excinfo.value, "reason", "") == "action_disabled"

    async def test_firewall_action_still_needs_operator_enabled(self) -> None:
        """İki bağımsız kapı: global flag açık ama operatör enable etmemiş → RED."""
        with pytest.raises(Exception) as excinfo:
            evaluate_proposal(
                ACTION_BLOCK_SRC_IP,
                {"ip": "203.0.113.7"},
                make_evidence(),
                action_enabled=False,
                allow_blocked_actions=True,
            )
        assert getattr(excinfo.value, "reason", "") == "action_disabled"

    async def test_firewall_action_passes_only_with_both_gates(self) -> None:
        decision = evaluate_proposal(
            ACTION_BLOCK_SRC_IP,
            {"ip": "203.0.113.7"},
            make_evidence(),
            action_enabled=True,
            allow_blocked_actions=True,
        )
        assert decision.allowed is True
        names = [c.name for c in decision.checks]
        assert names == [
            "action_in_allowlist",
            "params_valid",
            "action_enabled",
            "default_blocked_gate",
            "target_scope",
        ]

    async def test_isolate_host_denied_by_default(self) -> None:
        with pytest.raises(DefaultBlockedError):
            evaluate_proposal(
                ACTION_ISOLATE_HOST,
                {"agent_id": "001"},
                make_evidence(),
                action_enabled=True,
                allow_blocked_actions=False,
            )


class TestTargetScope:
    async def test_wrong_agent_id_rejected(self) -> None:
        """'yanlış hedef': agent_id kanıtta yok → RED."""
        with pytest.raises(TargetScopeError):
            evaluate_proposal(
                ACTION_RESTART_WAZUH_AGENT,
                {"agent_id": "999"},
                make_evidence(),
                action_enabled=True,
                allow_blocked_actions=False,
            )

    async def test_wrong_ip_rejected(self) -> None:
        """'yanlış hedef': IP kanıt src_ips içinde değil → RED."""
        with pytest.raises(TargetScopeError):
            evaluate_proposal(
                ACTION_BLOCK_SRC_IP,
                {"ip": "198.51.100.99"},
                make_evidence(),
                action_enabled=True,
                allow_blocked_actions=True,
            )

    async def test_matching_ip_passes(self) -> None:
        decision = evaluate_proposal(
            ACTION_BLOCK_SRC_IP,
            {"ip": "203.0.113.7"},
            make_evidence(),
            action_enabled=True,
            allow_blocked_actions=True,
        )
        assert decision.allowed is True

    async def test_empty_evidence_fails_any_event_scope(self) -> None:
        with pytest.raises(TargetScopeError):
            evaluate_proposal(
                ACTION_NOTIFY_ADMIN,
                {},
                make_evidence(event_ids=[]),
                action_enabled=True,
                allow_blocked_actions=False,
            )


class TestExecutionRevalidation:
    async def test_observe_only_mode_blocks_execution(self) -> None:
        """observe_only: YÜRÜTME YASAK — ModeBlockedError (executor'a ulaşılmaz)."""
        definition = __import__(
            "app.services.remediation.catalog", fromlist=["get_action_definition"]
        ).get_action_definition(ACTION_RESTART_WAZUH_AGENT)
        assert definition is not None
        with pytest.raises(ModeBlockedError):
            revalidate_for_execution(
                definition,
                {"agent_id": "001"},
                make_evidence(),
                action_enabled=True,
                allow_blocked_actions=False,
                policy_mode=POLICY_MODE_OBSERVE_ONLY,
            )

    async def test_dry_run_mode_allows_revalidation(self) -> None:
        from app.services.remediation.catalog import get_action_definition

        definition = get_action_definition(ACTION_RESTART_WAZUH_AGENT)
        assert definition is not None
        decision = revalidate_for_execution(
            definition,
            {"agent_id": "001"},
            make_evidence(),
            action_enabled=True,
            allow_blocked_actions=False,
            policy_mode=POLICY_MODE_DRY_RUN,
        )
        assert decision.allowed is True

    async def test_execution_revalidation_rejects_wrong_target(self) -> None:
        """Onay sonrası kanıt değişse bile yürütmede hedef yeniden doğrulanır."""
        from app.services.remediation.catalog import get_action_definition

        definition = get_action_definition(ACTION_RESTART_WAZUH_AGENT)
        assert definition is not None
        with pytest.raises(TargetScopeError):
            revalidate_for_execution(
                definition,
                {"agent_id": "001"},
                make_evidence(agent_ids=["999"]),  # kanıt artık başka agent
                action_enabled=True,
                allow_blocked_actions=False,
                policy_mode=POLICY_MODE_DRY_RUN,
            )


class TestDecisionTrace:
    async def test_decision_to_dict_shape(self) -> None:
        decision = evaluate_proposal(
            ACTION_NOTIFY_ADMIN, {}, make_evidence(),
            action_enabled=True, allow_blocked_actions=False,
        )
        payload = decision.to_dict()
        assert payload["allowed"] is True
        assert all(c["passed"] for c in payload["checks"])
        assert {c["name"] for c in payload["checks"]} == {
            "action_in_allowlist",
            "params_valid",
            "action_enabled",
            "default_blocked_gate",
            "target_scope",
        }

    async def test_engine_is_deterministic(self) -> None:
        """Aynı girdi → aynı karar (LLM bağımlılığı YOK)."""
        args = (ACTION_RESTART_WAZUH_AGENT, {"agent_id": "001"}, make_evidence())
        kwargs = {"action_enabled": True, "allow_blocked_actions": False}
        first = evaluate_proposal(*args, **kwargs).to_dict()
        second = evaluate_proposal(*args, **kwargs).to_dict()
        assert first == second
