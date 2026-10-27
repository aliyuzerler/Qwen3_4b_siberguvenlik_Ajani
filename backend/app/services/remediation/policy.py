"""Deterministik politika motoru (Faz 07).

Gereksinimler (phases/07-remediation-guardrails.md + AGENTS.md §4):
- "Model eylemi doğrudan başlatamaz; policy engine ve yetkili backend
  başlatır" → motor SAF ve deterministiktir: girdi (tanım + param + kanıt
  paketi) aynıysa karar aynıdır; LLM çıktısına erişimi, bağımlılığı YOKTUR.
- Kontrol sırası (fail-fast, hepsi audit'e yazılan karar izinde):
    1. action_in_allowlist  : tip katalogda tanımlı mı?
    2. params_valid         : tip şeması (extra=forbid — serbest komut reddi)
    3. action_enabled       : operatör kataloğu DB'de enabled mi?
    4. default_blocked_gate : firewall/SSH/hesap → global env + admin enable
    5. target_scope         : hedef değeri kanıt paketiyle eşleşiyor mu?
- "yanlış hedef" reddi: hedef kapsam (SCOPE_*) kanıttaki değerlerle
  karşılaştırılır; eşleşme yoksa TargetScopeError.

Karar izi (checks) öneri satırına JSONB olarak yazılır — "neden
reddedildi/onaylandı" sorusu panel ve audit üzerinden cevaplanabilir.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.services.remediation.catalog import (
    SCOPE_AGENT_ID,
    SCOPE_SRC_IP,
    ActionDefinition,
)
from app.services.remediation.errors import (
    DefaultBlockedError,
    InvalidParamsError,
    ModeBlockedError,
    PolicyBlockedError,
    TargetScopeError,
    UnknownActionTypeError,
)

POLICY_MODE_OBSERVE_ONLY = "observe_only"
POLICY_MODE_DRY_RUN = "dry_run"


@dataclass(frozen=True, slots=True)
class PolicyCheck:
    """Tek politika kontrolünün izi (panel/audit görünür)."""

    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Politika kararı + tam kontrol izi (JSONB'ye yazılır)."""

    allowed: bool
    checks: tuple[PolicyCheck, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "checks": [
                {"name": c.name, "passed": c.passed, "detail": c.detail}
                for c in self.checks
            ],
        }


def _fail(checks: list[PolicyCheck], error: PolicyBlockedError) -> PolicyBlockedError:
    error.detail = {"checks": [_check_dict(c) for c in checks], **error.detail}
    return error


def _check_dict(check: PolicyCheck) -> dict[str, Any]:
    return {"name": check.name, "passed": check.passed, "detail": check.detail}


def evaluate_proposal(
    action_type: str,
    raw_params: dict[str, Any],
    evidence: dict[str, Any],
    *,
    action_enabled: bool,
    allow_blocked_actions: bool,
) -> PolicyDecision:
    """Öneri (create) anındaki tam politika değerlendirmesi.

    Reddedilirse PolicyBlockedError alt sınıfı fırlatır (API → 422; audit
    → remediation.action.blocked). Kabulde allowed=True karar izi döner.
    """
    checks: list[PolicyCheck] = []

    # --- 1) Allowlist (tipli enum; serbest komut yok) ---
    definition: ActionDefinition | None = None
    from app.services.remediation.catalog import get_action_definition

    definition = get_action_definition(action_type)
    checks.append(
        PolicyCheck(
            name="action_in_allowlist",
            passed=definition is not None,
            detail=action_type if definition is not None else "katalogda tanımlı değil",
        )
    )
    if definition is None:
        raise _fail(checks, UnknownActionTypeError(action_type))

    # --- 2) Tip param doğrulaması (extra=forbid → command/args/shell reddi) ---
    try:
        params = definition.validate_params(raw_params)
        checks.append(
            PolicyCheck(
                name="params_valid",
                passed=True,
                detail=", ".join(sorted(params)) or "(param yok)",
            )
        )
    except Exception as exc:  # pydantic ValidationError (ve türevleri)
        checks.append(PolicyCheck(name="params_valid", passed=False, detail=str(exc)[:200]))
        raise _fail(
            checks,
            InvalidParamsError(
                "Aksiyon parametreleri tip şemasına uymuyor; serbest alan/komut "
                "kabul edilmez.",
                detail={"action_type": action_type},
            ),
        ) from exc

    # --- 3) Operatör anahtarı (DB'de enabled; admin PATCH ile değişir) ---
    checks.append(
        PolicyCheck(
            name="action_enabled",
            passed=action_enabled,
            detail="etkin" if action_enabled else "operatör tarafından devre dışı",
        )
    )
    if not action_enabled:
        raise _fail(
            checks,
            PolicyBlockedError(
                reason="action_disabled",
                message=f"'{action_type}' aksiyonu operatör tarafından devre dışı bırakılmış.",
                detail={"action_type": action_type},
            ),
        )

    # --- 4) Varsayılan engelli aksiyonlar (firewall/SSH/hesap) ---
    if definition.default_blocked:
        gate_open = allow_blocked_actions
        checks.append(
            PolicyCheck(
                name="default_blocked_gate",
                passed=gate_open,
                detail=(
                    "REMEDIATION_ALLOW_BLOCKED_ACTIONS=true"
                    if gate_open
                    else definition.blocked_detail
                ),
            )
        )
        if not gate_open:
            raise _fail(checks, DefaultBlockedError(definition.blocked_detail))
    else:
        checks.append(
            PolicyCheck(name="default_blocked_gate", passed=True, detail="N/A (engelli değil)")
        )

    # --- 5) Hedef kapsam (kanıt paketiyle eşleşme) ---
    scope_check, scope_error = _evaluate_target_scope(definition, params, evidence)
    checks.append(scope_check)
    if scope_error is not None:
        raise _fail(checks, scope_error)

    return PolicyDecision(allowed=True, checks=tuple(checks))


def revalidate_for_execution(
    definition: ActionDefinition,
    params: dict[str, Any],
    evidence: dict[str, Any],
    *,
    action_enabled: bool,
    allow_blocked_actions: bool,
    policy_mode: str,
) -> PolicyDecision:
    """Yürütme öncesi TAM yeniden değerlendirme (savunma derinliği).

    Onay ile yürütme arasında katalog/tanım değişmiş olabilir; politikaya
    uymayan bir durum yürütülmez. Ek olarak mode kapısı: observe_only
    → yürütme YASAK (dry_run hariç hiçbir mod kodda YOKTUR).
    """
    if policy_mode != POLICY_MODE_DRY_RUN:
        # observe_only (ve gelecekteki bilinmeyen modlar) yürütmeyi reddeder.
        raise ModeBlockedError()
    decision = evaluate_proposal(
        definition.key,
        params,
        evidence,
        action_enabled=action_enabled,
        allow_blocked_actions=allow_blocked_actions,
    )
    return decision


def _evaluate_target_scope(
    definition: ActionDefinition,
    params: dict[str, Any],
    evidence: dict[str, Any],
) -> tuple[PolicyCheck, PolicyBlockedError | None]:
    """Hedef kapsam kuralı: param değeri kanıt paketinde bulunmalıdır."""
    scope = definition.target_scope
    if scope == SCOPE_AGENT_ID:
        agent_ids = {str(v) for v in evidence.get("agent_ids", [])}
        target = str(params.get("agent_id", ""))
        ok = target in agent_ids
        return (
            PolicyCheck(
                name="target_scope",
                passed=ok,
                detail=f"agent_id={target!r} kanıt agent_ids içinde {'VAR' if ok else 'YOK'}",
            ),
            None
            if ok
            else TargetScopeError(
                "Hedef agent_id kanıt paketindeki olaylarla eşleşmiyor (yanlış hedef).",
                detail={"target": target, "known": sorted(agent_ids)},
            ),
        )
    if scope == SCOPE_SRC_IP:
        src_ips = {str(v) for v in evidence.get("src_ips", [])}
        target = str(params.get("ip", ""))
        ok = target in src_ips
        return (
            PolicyCheck(
                name="target_scope",
                passed=ok,
                detail=f"ip={target!r} kanıt src_ips içinde {'VAR' if ok else 'YOK'}",
            ),
            None
            if ok
            else TargetScopeError(
                "Hedef IP, kanıt olaylarının kaynak IP'leriyle eşleşmiyor (yanlış hedef).",
                detail={"target": target, "known": sorted(src_ips)},
            ),
        )
    # SCOPE_ANY_EVENT: kanıt paketi en az bir olay içerir (servis garantisi).
    ok = len(evidence.get("event_ids", [])) >= 1
    return (
        PolicyCheck(
            name="target_scope",
            passed=ok,
            detail=f"bağlı olay sayısı={len(evidence.get('event_ids', []))}",
        ),
        None
        if ok
        else TargetScopeError(
            "Öneri en az bir kanıt olayı gerektirir.",
            detail={"event_count": len(evidence.get("event_ids", []))},
        ),
    )


__all__ = [
    "POLICY_MODE_DRY_RUN",
    "POLICY_MODE_OBSERVE_ONLY",
    "PolicyCheck",
    "PolicyDecision",
    "evaluate_proposal",
    "revalidate_for_execution",
]
