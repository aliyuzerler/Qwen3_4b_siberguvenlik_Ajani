"""Müdahale yürütücü katmanı (Faz 07).

Gereksinimler (phases/07-remediation-guardrails.md):
- "İlk testlerde gerçek sistem değişikliği yerine fake executor kullan."
- "timeout" (kabul satırı) → executor çağrısı asyncio.wait_for ile sınırılır;
  aşılırsa aksiyon status=failed + error_code=executor_timeout.

EN KRİTİK GARANTİ: BU PAKETTE GERÇEK YÜRÜTÜCÜ SINIFI YOKTUR. Tek somut
uygulama DryRunExecutor'dur — hiçbir alt süreci başlatmaz, ağ çağrısı
yapmaz, dosya değiştirmez; yalnızca "ne yapılacaktı" planını kayıtlı
döndürür (test_remediation_security kaynak taraması: subprocess/os.system/
socket/eval yasak; ikinci bir *Executor sınıfı yasak).

Gerçek entegrasyonlar (Wazuh API/EDR/firewall) BU FAZDA yazılmaz; yazılsa
bile politika motoru + admin yürütme uçlarından geçmeden hiçbir kod yolu
onlara ulaşamaz (observe_only/dry_run enum'u dışında mod YOKTUR).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.core.logging import get_logger
from app.services.remediation import catalog as catalog_mod

logger = get_logger(__name__)

# Yürütme sonuç hata kodları
ERROR_EXECUTOR_TIMEOUT = "executor_timeout"
ERROR_EXECUTOR_FAILURE = "executor_failure"

SIMULATED_TRUE = True  # DryRunExecutor çıktısı DAIMA simülasyondur


@dataclass(slots=True)
class ExecutionResult:
    """Tek yürütme denemesinin sonucu (satıra JSONB olarak yazılır)."""

    success: bool
    simulated: bool = SIMULATED_TRUE
    error_code: str | None = None
    error_message: str | None = None
    duration_ms: int = 0
    output: dict[str, Any] = field(default_factory=dict)


class ActionExecutor(Protocol):
    """Yürütücü sözleşmesi (gelecek gerçek entegrasyonlar bu protokolü sağlar)."""

    async def execute(
        self,
        action_type: str,
        params: dict[str, Any],
        evidence: dict[str, Any],
    ) -> ExecutionResult:
        """Aksiyonu yürütür; SONUÇ döndürür (istisna fırlatmadan)."""
        ...  # pragma: no cover


class DryRunExecutor:
    """Kuru koşu yürütücüsü: SİMÜLASYON — sistemde hiçbir değişiklik yapmaz.

    - execute(): katalogdaki execution_plan metnini (TR) çıktıya yazar;
      `simulated=true` etiketiyle döndürür. Panelde "SİMÜLASYON" rozeti
      bu değerle üretilir; operatör sahte başarı görmez (mock AI yasağı
      ile aynı dürüstlük ilkesi: simülasyon olduğu AÇIK etiketlenir).
    """

    async def execute(
        self,
        action_type: str,
        params: dict[str, Any],
        evidence: dict[str, Any],
    ) -> ExecutionResult:
        started = time.monotonic()
        definition = catalog_mod.get_action_definition(action_type)
        plan = (
            definition.execution_plan
            if definition is not None
            else "Katalog dışı aksiyon — yürütülmedi."
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        return ExecutionResult(
            success=True,
            simulated=True,
            duration_ms=duration_ms,
            output={
                "plan": plan,
                "mode": "dry_run",
                "params": dict(params),
                "target_event_count": len(evidence.get("event_ids", [])),
            },
        )


async def execute_with_timeout(
    executor: ActionExecutor,
    *,
    action_type: str,
    params: dict[str, Any],
    evidence: dict[str, Any],
    timeout_seconds: float,
) -> ExecutionResult:
    """Executor çağrısını zaman sınırıyla çalıştırır (kabul: timeout).

    - TimeoutError → success=False + error_code=executor_timeout
    - Beklenmeyen istisna → success=False + error_code=executor_failure
      (yürütücü hatası akışı çökertmez; durum satıra yazılır, audit'e düşer)
    """
    started = time.monotonic()
    try:
        result = await asyncio.wait_for(
            executor.execute(action_type, params, evidence),
            timeout=timeout_seconds,
        )
    except TimeoutError:
        duration_ms = int((time.monotonic() - started) * 1000)
        logger.warning(
            "remediation_executor_timeout",
            action_type=action_type,
            timeout_seconds=timeout_seconds,
        )
        return ExecutionResult(
            success=False,
            simulated=True,
            error_code=ERROR_EXECUTOR_TIMEOUT,
            error_message=(
                f"Yürütücü {timeout_seconds} saniye içinde yanıt vermedi."
            ),
            duration_ms=duration_ms,
        )
    except Exception as exc:  # noqa: BLE001 — yürütücü hatası izole edilir
        duration_ms = int((time.monotonic() - started) * 1000)
        logger.exception("remediation_executor_failure", action_type=action_type)
        return ExecutionResult(
            success=False,
            simulated=True,
            error_code=ERROR_EXECUTOR_FAILURE,
            error_message=f"Yürütücü beklenmeyen hata: {type(exc).__name__}",
            duration_ms=duration_ms,
        )
    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


__all__ = [
    "ERROR_EXECUTOR_FAILURE",
    "ERROR_EXECUTOR_TIMEOUT",
    "ActionExecutor",
    "DryRunExecutor",
    "ExecutionResult",
    "execute_with_timeout",
]
