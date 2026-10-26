"""WazuhAlert → NormalizedEvent dönüşümü (Faz 03).

Kontrollü alan eşlemesi (phases/03): yalnızca whitelisted alanlar taşınır;
rastgele alan passthrough YOKTUR (ham alert ayrı, opsiyonel `raw` sütununda
 Politikaya göre saklanır — varsayılan kapalı, gerekçesi belgelenmiştir).

Redaction sırası:
1. full_log uzunluk sınırına kırpılır (MAX_FULL_LOG_CHARS — DoS yüzeyini sınırlar)
2. secret desenleri + e-posta maskesi uygulanır
3. src_ip politikaya göre maskelenir
4. fingerprint MASKED içerik üzerinden hesaplanır (secret hash girdisine girmez)

Zorunlu alan koruması: WazuhAlert üretimi (parsing.py) zaten id/timestamp/rule
alanlarını zorunlu kılar; bu katman savunma derinliği olarak boş/eksik alanlarda
NormalizationError fırlatır (AGENTS.md §7: negatif yollar testlidir).
"""

from __future__ import annotations

from app.services.normalization.errors import NormalizationError
from app.services.normalization.models import NormalizedEvent
from app.services.normalization.redaction import (
    MAX_FULL_LOG_CHARS,
    RedactionPolicy,
    redact_src_ip,
    redact_text,
)
from app.services.wazuh.models import WazuhAlert

__all__ = ["normalize_alert"]


def _require_text(label: str, value: str | None) -> str:
    if value is None or not value.strip():
        raise NormalizationError(f"Zorunlu alan boş/eksik: {label}.")
    return value.strip()


def normalize_alert(alert: WazuhAlert, policy: RedactionPolicy) -> NormalizedEvent:
    """Tek Wazuh alert'ini sürümlenmiş event modeline dönüştürür."""
    alert_id = _require_text("alert_id", alert.alert_id)
    rule_id = _require_text("rule_id", alert.rule_id)
    rule_description = _require_text("rule_description", alert.rule_description)

    full_log = alert.full_log
    if full_log and len(full_log) > MAX_FULL_LOG_CHARS:
        full_log = full_log[:MAX_FULL_LOG_CHARS]
    full_log_redacted = redact_text(full_log, policy) if full_log else None

    event = NormalizedEvent(
        alert_id=alert_id,
        timestamp=alert.timestamp,
        rule_id=rule_id,
        rule_level=alert.rule_level,  # ORİJİNAL severity — asla dönüştürülmez
        rule_description=redact_text(rule_description, policy),
        rule_groups=list(alert.rule_groups),
        agent_id=alert.agent_id,
        agent_name=alert.agent_name,
        manager=alert.manager,
        location=alert.location,
        decoder=alert.decoder,
        full_log_redacted=full_log_redacted,
        src_ip=redact_src_ip(alert.src_ip, policy),
    )
    return event
