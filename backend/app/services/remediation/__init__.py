"""Güvenli müdahale hazırlık servisi (Faz 07).

Paket içeriği:
- catalog : tipli aksiyon kataloğu (allowlist; serbest shell komutu YOK)
- policy  : deterministik politika motoru (karar izi audit'e yazılır)
- executor: DryRunExecutor (TEK somut yürütücü; simülasyon) + timeout
- service : öneri/onay/yürütme orkestrasyonu + kanıt paketi + replay koruması
- errors  : yapılandırılmış red türleri (API 4xx'e çevrilir)

EN KRİTİK GARANTİ: bu pakette gerçek sistem değişikliği yapan KOD YOLU
YOKTUR. DryRunExecutor yalnızca "ne yapılacaktı" planını döndürür;
yürütme observe_only modunda yasak, dry_run modunda daima simülasyondur.
Model (LLM) bu paketi hiçbir yoldan çağıramaz (kaynak tarama testi).
"""

from __future__ import annotations

from app.services.remediation.catalog import (
    ALL_ACTION_TYPES,
    ActionDefinition,
    get_action_definition,
    list_action_definitions,
)
from app.services.remediation.errors import (
    DefaultBlockedError,
    InvalidParamsError,
    KillSwitchError,
    ModeBlockedError,
    PolicyBlockedError,
    RemediationError,
    StateError,
    TargetScopeError,
    UnknownActionTypeError,
)
from app.services.remediation.executor import (
    ActionExecutor,
    DryRunExecutor,
    ExecutionResult,
)
from app.services.remediation.policy import PolicyDecision
from app.services.remediation.service import (
    MAX_EVIDENCE_EVENTS,
    approve_action,
    build_evidence,
    create_proposal,
    execute_action,
    get_enabled_flags,
    list_actions,
    reject_action,
    set_action_enabled,
    sync_remediation_catalog,
)

__all__ = [
    "ALL_ACTION_TYPES",
    "MAX_EVIDENCE_EVENTS",
    "ActionDefinition",
    "ActionExecutor",
    "DefaultBlockedError",
    "DryRunExecutor",
    "ExecutionResult",
    "InvalidParamsError",
    "KillSwitchError",
    "ModeBlockedError",
    "PolicyBlockedError",
    "PolicyDecision",
    "RemediationError",
    "StateError",
    "TargetScopeError",
    "UnknownActionTypeError",
    "approve_action",
    "build_evidence",
    "create_proposal",
    "execute_action",
    "get_action_definition",
    "get_enabled_flags",
    "list_action_definitions",
    "list_actions",
    "reject_action",
    "set_action_enabled",
    "sync_remediation_catalog",
]
