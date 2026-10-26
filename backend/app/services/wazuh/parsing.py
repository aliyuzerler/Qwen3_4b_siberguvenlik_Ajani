"""OpenSearch hit → WazuhAlert dönüşümü (Faz 02).

Gerçek indexer istemcisi ile mock kaynak AYNI dönüşümü kullanır:
sözleşme testleri böylece gerçek kod yolunu doğrular (mock-first, AGENTS.md §7).

Yalnızca gereken alanlar alınır (phases/02-wazuh-integration.md); ham alert
`raw` içinde izlenebilirlik için aynen korunur. Doğrulanmamış alanlara
güvenilmez (wazuh-integration skill §7): zorunlu alan eksikse WazuhBadPayloadError.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services.wazuh.errors import WazuhBadPayloadError
from app.services.wazuh.models import WazuhAlert


def _require(source: dict[str, Any], dotted: str) -> Any:
    """Noktalı yol ile alan okur; yoksa WazuhBadPayloadError fırlatır."""
    node: Any = source
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            raise WazuhBadPayloadError(
                f"Wazuh alert yanıtı beklenen alanı içermiyor: '{dotted}'. "
                "Yanıt şeması sürümle değişmiş olabilir; adapter güncellenmelidir."
            )
        node = node[part]
    return node


def _optional(source: dict[str, Any], dotted: str) -> str | None:
    node: Any = source
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    if node is None:
        return None
    return str(node)


def _parse_timestamp(value: Any) -> datetime:
    """Wazuh timestamp (örn. '2026-10-26T09:15:00.000+0000') → UTC datetime."""
    if not isinstance(value, str):
        raise WazuhBadPayloadError("Wazuh alert 'timestamp' alanı metin değil.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WazuhBadPayloadError(
            "Wazuh alert 'timestamp' değeri çözümlenemedi: biçim beklenmedik."
        ) from exc
    if parsed.tzinfo is None:
        # Indexer timestamp'leri UTC saklar; tz'siz değer UTC sayılır.
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_alert_hit(hit: dict[str, Any]) -> WazuhAlert:
    """Tek OpenSearch hit'ini WazuhAlert'e dönüştürür."""
    source = hit.get("_source") if isinstance(hit, dict) else None
    if not isinstance(source, dict):
        raise WazuhBadPayloadError(
            "Wazuh alert hit'i '_source' nesnesi içermiyor; yanıt bozuk."
        )

    rule_level_raw = _require(source, "rule.level")
    if isinstance(rule_level_raw, bool) or not isinstance(rule_level_raw, (int, float)):
        raise WazuhBadPayloadError("'rule.level' sayısal değil (0-15 beklenir).")
    rule_level = int(rule_level_raw)
    if not 0 <= rule_level <= 15:
        raise WazuhBadPayloadError(
            f"'rule.level' 0-15 aralığının dışında: {rule_level}."
        )

    alert_id = str(source.get("id") or hit.get("_id") or "").strip()
    if not alert_id:
        raise WazuhBadPayloadError("Alert kimliği boş: 'id' alanı yok.")

    rule_node = source.get("rule")
    groups_raw = rule_node.get("groups", []) if isinstance(rule_node, dict) else []
    rule_groups = [str(g) for g in groups_raw] if isinstance(groups_raw, list) else []

    data_node: Any = source.get("data")
    data: dict[str, Any] = data_node if isinstance(data_node, dict) else {}
    src_ip = data.get("srcip") or data.get("src_ip")

    return WazuhAlert(
        alert_id=alert_id,
        timestamp=_parse_timestamp(source.get("timestamp")),
        rule_id=str(_require(source, "rule.id")),
        rule_level=rule_level,
        rule_description=str(_require(source, "rule.description")),
        rule_groups=rule_groups,
        agent_id=_optional(source, "agent.id"),
        agent_name=_optional(source, "agent.name"),
        location=_optional(source, "location"),
        decoder=_optional(source, "decoder.name"),
        manager=_optional(source, "manager.name"),
        full_log=_optional(source, "full_log"),
        src_ip=str(src_ip) if src_ip is not None else None,
        raw=source,
    )
