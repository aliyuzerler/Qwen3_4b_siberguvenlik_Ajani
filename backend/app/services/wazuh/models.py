"""Wazuh alert iç modelleri (Faz 02) — tipli, dış API'den bağımsız sözleşme.

Korunması zorunlu alanlar (phases/02-wazuh-integration.md, wazuh-integration skill §6):
- Alert ID (Wazuh `id`: epoch.mikrosaniye), timestamp, agent, rule ve
  ORİJİNAL severity (rule.level 0-15; LLM asla bunun üzerine yazamaz, AGENTS.md §5).

Zaman normalizasyonu: Wazuh Indexer timestamp'leri UTC saklar; tz'li değerler
UTC'ye çevrilir, tz'siz (naive) değerler UTC varsayımıyla işaretlenir.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

# Kaba UI etiketi; kanonik severity daima rule_level int'tir.
# Wazuh dokümantasyonu: level 0-15, yükseldikçe ciddiyet artar; 0 = yoksayılır.
_SEVERITY_LABELS: tuple[tuple[int, str], ...] = (
    (0, "yoksayildi"),
    (3, "dusuk"),
    (6, "orta"),
    (15, "yuksek"),
)


def severity_label(level: int) -> str:
    """0-15 rule.level için kaba etiket döner (kanonik değer int kalır)."""
    for upper, label in _SEVERITY_LABELS:
        if level <= upper:
            return label
    return "yuksek"


def normalize_timestamp(value: datetime) -> datetime:
    """Timestamp'ı UTC'ye normalize eder (tz'siz → UTC varsayımı)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class AlertQuery(BaseModel):
    """Alert listeleme sorgusu: zaman penceresi + sayfalama."""

    since: datetime | None = None
    until: datetime | None = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)

    @field_validator("since", "until")
    @classmethod
    def _normalize_window(cls, value: datetime | None) -> datetime | None:
        return normalize_timestamp(value) if value is not None else None


class WazuhAlert(BaseModel):
    """Dış API'den dönüştürülmüş tek alert (izlenebilirlik alanları korunur)."""

    alert_id: str
    timestamp: datetime
    rule_id: str
    rule_level: int = Field(ge=0, le=15)  # ORİJİNAL Wazuh severity (kanonik)
    rule_description: str
    rule_groups: list[str] = Field(default_factory=list)
    agent_id: str | None = None
    agent_name: str | None = None
    location: str | None = None
    decoder: str | None = None
    manager: str | None = None
    full_log: str | None = None
    src_ip: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)  # ham alert (izlenebilirlik)

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return normalize_timestamp(value)

    @property
    def severity(self) -> str:
        return severity_label(self.rule_level)


class AlertPage(BaseModel):
    """Sayfalı alert listesi."""

    items: list[WazuhAlert]
    total: int | None = None  # indexer toplamı; bilinmiyorsa None
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=1000)

    @property
    def has_more(self) -> bool:
        if self.total is None:
            return len(self.items) == self.limit
        return self.offset + len(self.items) < self.total
