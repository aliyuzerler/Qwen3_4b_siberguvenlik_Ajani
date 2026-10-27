"""Müdahale servisi hata türleri (Faz 07).

Her hata türü deterministik bir politika reddine karşılık gelir; API
katmanı bu türleri yapılandırılmış 4xx yanıtlarına çevirir. Reddetme
nedenleri HER ZAMAN audit'e yazılır (remediation.action.blocked).
"""

from __future__ import annotations

from typing import Any


class RemediationError(Exception):
    """Temel müdahale hatası (code + kullanıcıya açık TR mesaj)."""

    def __init__(self, code: str, message: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail: dict[str, Any] = detail or {}


class KillSwitchError(RemediationError):
    """REMEDIATION_ENABLED=false: öneri ve yürütme tamamen kapalı (503)."""

    def __init__(self) -> None:
        super().__init__(
            code="kill_switch",
            message=(
                "Müdahale alt sistemi kill switch ile devre dışı "
                "(REMEDIATION_ENABLED=false). Açmak için docs/remediation-runbook.md §1."
            ),
        )


class PolicyBlockedError(RemediationError):
    """Deterministik politika reddi (422): mode/allowlist/blocked/scope."""

    def __init__(self, reason: str, message: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(code=reason, message=message, detail=detail)
        self.reason = reason


class TargetScopeError(PolicyBlockedError):
    """Hedef kapsam ihlali: parametre değeri kanıt paketiyle eşleşmiyor."""

    def __init__(self, message: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(reason="target_scope", message=message, detail=detail)


class InvalidParamsError(PolicyBlockedError):
    """Tip parametre doğrulaması başarısız (serbest alan dahil)."""

    def __init__(self, message: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(reason="invalid_params", message=message, detail=detail)


class UnknownActionTypeError(PolicyBlockedError):
    """Aksiyon tipi katalogda (allowlist) tanımlı değil."""

    def __init__(self, action_type: str) -> None:
        super().__init__(
            reason="unknown_action_type",
            message=(
                f"Aksiyon tipi '{action_type}' allowlist'te tanımlı değil. "
                "Serbest komut yok: yalnızca katalogdaki tipli aksiyonlar önerilebilir."
            ),
            detail={"action_type": action_type},
        )


class DefaultBlockedError(PolicyBlockedError):
    """Firewall/SSH/hesap aksiyonu: iki bağımsız kapı da açık değil."""

    def __init__(self, detail_text: str) -> None:
        super().__init__(reason="default_blocked", message=detail_text)


class ModeBlockedError(PolicyBlockedError):
    """policy_mode=observe_only: yürütme yok; yalnızca hazırlık/izleme."""

    def __init__(self) -> None:
        super().__init__(
            reason="mode_blocked",
            message=(
                "policy_mode=observe_only: müdahale YÜRÜTÜLEMEZ. Yalnızca "
                "dry_run modunda simülasyon yürütmesi yapılır "
                "(POLICY_MODE=dry_run; docs/remediation-runbook.md §1)."
            ),
        )


class StateError(RemediationError):
    """Durum makinesi ihlali / onay sorunları (409).

    - eksik onay (status != approved)
    - onaylayan == öneren (görev ayrımı)
    - onay TTL'i dolmuş (status → expired)
    - tekrar oynatılan istek, farklı idempotency anahtarıyla
    - katalog/aksiyon bulunamadı (404)
    """

    def __init__(self, code: str, message: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(code=code, message=message, detail=detail)


__all__ = [
    "DefaultBlockedError",
    "InvalidParamsError",
    "KillSwitchError",
    "ModeBlockedError",
    "PolicyBlockedError",
    "RemediationError",
    "StateError",
    "TargetScopeError",
    "UnknownActionTypeError",
]
