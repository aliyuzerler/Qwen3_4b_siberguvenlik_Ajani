"""Panel API şemaları (Faz 05) — istek/yanıt sözleşmeleri.

Kurallar:
- Parola/token/secret değeri HİÇBİR şemada YOKTUR (secret sızma yüzeyi
  tip seviyesinde kapatılır — response'lara alan eklenemez).
- Olay yanıtlarında ORİJİNAL Wazuh alanları (rule_level) ile model
  değerlendirmesi (ai_assessment) AYRI nesnelerde taşınır (AGENTS.md §5:
  "Model çıktısı alarmın severity alanını üzerine yazmamalı").
- Tüm zaman alanları UTC ISO-8601'dir.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# --- Auth -----------------------------------------------------------------


class LoginRequest(BaseModel):
    """Giriş isteği (model çıktısı DEĞİLDİR; kullanıcı girdisi — doğrulanır)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=16, max_length=4096)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105  # HTTP auth şeması adı
    expires_in: int


class MeResponse(BaseModel):
    id: str
    username: str
    role: str


# --- Events ----------------------------------------------------------------


class AnalysisSummary(BaseModel):
    """Olay liste/detay yanıtlarındaki model kaydı özeti (ayrı nesne)."""

    status: Literal["completed", "analysis_failed"]
    ai_assessment: str | None = None
    confidence: float | None = None
    requires_human_review: bool | None = None
    model_tag: str
    finished_at: datetime


class EventListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    source: str
    alert_id: str
    agent_id: str | None = None
    agent_name: str | None = None
    manager: str | None = None
    rule_id: str
    rule_level: int = Field(ge=0, le=15)  # ORİJİNAL Wazuh severity
    rule_description: str
    rule_groups: list[str] = []
    seen_count: int
    variant_count: int
    # Model değerlendirmesi AYRI alanda: yoksa None (henüz analiz edilmedi)
    analysis: AnalysisSummary | None = None


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    field: str | None = None
    value: Any = None


class AnalysisDetail(AnalysisSummary):
    """Olay detayındaki tam model kaydı (metin alanları dahil)."""

    summary: str | None = None
    evidence: list[EvidenceItem] = []
    alternative_explanations: list[str] = []
    recommended_next_steps: list[str] = []
    error_code: str | None = None
    error_message: str | None = None
    prompt_template_version: str
    duration_ms: int
    retries_used: int


class EventDetail(EventListItem):
    location: str | None = None
    decoder: str | None = None
    src_ip: str | None = None
    full_log_redacted: str | None = None
    received_at: datetime
    last_seen_at: datetime | None = None
    analysis: AnalysisDetail | None = None


class EventListResponse(BaseModel):
    items: list[EventListItem]
    total: int
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    pages: int = Field(ge=0)


# --- Overview / Agents -----------------------------------------------------


class ComponentStatus(BaseModel):
    database: str
    wazuh: str
    ollama: str


class OverviewCounts(BaseModel):
    total_events: int
    events_24h: int
    analyses_completed: int
    analyses_failed: int
    pending_analysis: int


class OverviewByAssessment(BaseModel):
    benign: int = 0
    suspicious: int = 0
    malicious: int = 0
    unknown: int = 0


class OverviewResponse(BaseModel):
    components: ComponentStatus
    counts: OverviewCounts
    by_assessment: OverviewByAssessment
    recent: list[EventListItem]
    model: ModelInfo


class ModelInfo(BaseModel):
    """Model künyesi (secret değil; /ready + settings ile tutarlı)."""

    model_tag: str
    model_quantization: str
    analysis_enabled: bool
    policy_mode: str


class AgentRow(BaseModel):
    agent_id: str | None
    agent_name: str | None
    manager: str | None
    event_count: int = Field(ge=0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class AgentListResponse(BaseModel):
    items: list[AgentRow]
    total: int


# --- Audit -----------------------------------------------------------------


class AuditEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    actor: str
    action: str
    resource: str
    detail: dict[str, Any] | None = None
    client_ip: str | None = None
    request_id: str | None = None


class AuditListResponse(BaseModel):
    items: list[AuditEntry]
    total: int
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    pages: int = Field(ge=0)


# --- Settings (admin; secret değeri YOK) -----------------------------------


class SettingsResponse(BaseModel):
    """Panel ayar görünümü — değerler yalnızca okunur, secret ASLA dönmez.

    Kasıtlı olarak bulunmayan alanlar: jwt_secret, wazuh_indexer_password,
    admin_bootstrap_password (ve tüm credential benzeri değerler).
    wazuh_indexer_user dahil DEĞİLDİR: kullanıcı adı da credential sayılır.
    """

    app_env: str
    policy_mode: str
    model: ModelInfo
    ollama_base_url: str
    retention_days: int
    redaction: RedactionSettings
    worker: WorkerSettings
    notifications: NotificationSettings


class RedactionSettings(BaseModel):
    enabled: bool
    ip_mode: str
    email_mode: str
    secret_patterns: bool


class WorkerSettings(BaseModel):
    loop_enabled: bool
    interval_seconds: float
    concurrency: int
    batch_size: int


class NotificationSettings(BaseModel):
    """Faz 08+ yol haritası yeri (şimdilik boş yapı — UI roadmap kartı)."""

    enabled: bool = False
    roadmap_note: str = "Bildirimler Faz 08'te planlanacaktır."


# --- Correlations (Faz 06) ---------------------------------------------------
#
# Kural çıktısı ile LLM yorumu AYRI taşınır: korelasyon şemalarında HİÇBİR
# ai_* alanı yoktur; bağlı olayların model kayıtları AnalysisSummary olarak,
# olay başına AYRI nesnede gelir (AGENTS.md §5/§8).


class CorrelationListItem(BaseModel):
    """Korelasyon liste satırı: kural kimliği + pencere + tekrar sayaçları."""

    id: str
    rule_key: str
    rule_name: str
    rule_version: int = Field(ge=1)
    window_start: datetime
    window_end: datetime
    event_count: int = Field(ge=1)
    max_rule_level: int = Field(ge=0, le=15)
    hit_count: int = Field(ge=1)
    first_hit_at: datetime
    last_hit_at: datetime
    evidence: dict[str, Any]


class CorrelationLinkedEvent(BaseModel):
    """Korelasyona bağlı olay: orijinal kanıt + AYRI model kaydı özeti."""

    id: str
    timestamp: datetime
    alert_id: str
    rule_id: str
    rule_level: int
    rule_description: str
    agent_name: str | None = None
    src_ip: str | None = None
    analysis: AnalysisSummary | None = None  # LLM yorumu ayrı nesne


class CorrelationDetail(CorrelationListItem):
    created_at: datetime
    events: list[CorrelationLinkedEvent] = Field(default_factory=list)


class CorrelationListResponse(BaseModel):
    items: list[CorrelationListItem]
    total: int
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    pages: int = Field(ge=0)


class CorrelationRuleItem(BaseModel):
    """Kural kataloğu satırı (secret yok; params açıklanabilir yapıdadır)."""

    key: str
    name: str
    description: str
    version: int = Field(ge=1)
    kind: str
    params: dict[str, Any]
    enabled: bool
    created_at: datetime
    updated_at: datetime


class CorrelationRuleListResponse(BaseModel):
    items: list[CorrelationRuleItem]


class CorrelationRuleUpdateRequest(BaseModel):
    """Kural etkinlik güncellemesi (admin; değişim audit'e yazılır)."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool


class CorrelationRuleUpdateResponse(BaseModel):
    key: str
    enabled: bool
    result: str  # "updated" | "unchanged"
