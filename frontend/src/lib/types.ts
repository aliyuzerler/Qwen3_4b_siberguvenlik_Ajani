/** Backend API şemalarının TypeScript aynası (app/api/v1/schemas.py). */

export type Role = "viewer" | "analyst" | "admin";

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  expires_in: number;
}

export interface MeResponse {
  id: string;
  username: string;
  role: Role;
}

export interface AnalysisSummary {
  status: "completed" | "analysis_failed";
  ai_assessment: string | null;
  confidence: number | null;
  requires_human_review: boolean | null;
  model_tag: string;
  finished_at: string;
}

export interface EvidenceItem {
  field?: string;
  value?: unknown;
  [key: string]: unknown;
}

export interface AnalysisDetail extends AnalysisSummary {
  summary: string | null;
  evidence: EvidenceItem[];
  alternative_explanations: string[];
  recommended_next_steps: string[];
  error_code: string | null;
  error_message: string | null;
  prompt_template_version: string;
  duration_ms: number;
  retries_used: number;
}

export interface EventListItem {
  id: string;
  timestamp: string;
  source: string;
  alert_id: string;
  agent_id: string | null;
  agent_name: string | null;
  manager: string | null;
  rule_id: string;
  rule_level: number;
  rule_description: string;
  rule_groups: string[];
  seen_count: number;
  variant_count: number;
  analysis: AnalysisSummary | null;
}

export interface EventDetail extends EventListItem {
  location: string | null;
  decoder: string | null;
  src_ip: string | null;
  full_log_redacted: string | null;
  received_at: string;
  last_seen_at: string | null;
  analysis: AnalysisDetail | null;
}

export interface EventListResponse {
  items: EventListItem[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface OverviewResponse {
  components: { database: string; wazuh: string; ollama: string };
  counts: {
    total_events: number;
    events_24h: number;
    analyses_completed: number;
    analyses_failed: number;
    pending_analysis: number;
  };
  by_assessment: { benign: number; suspicious: number; malicious: number; unknown: number };
  recent: EventListItem[];
  model: {
    model_tag: string;
    model_quantization: string;
    analysis_enabled: boolean;
    policy_mode: string;
  };
}

export interface AgentListResponse {
  items: {
    agent_id: string | null;
    agent_name: string | null;
    manager: string | null;
    event_count: number;
    first_seen: string | null;
    last_seen: string | null;
  }[];
  total: number;
}

export interface AuditListResponse {
  items: {
    id: string;
    created_at: string;
    actor: string;
    action: string;
    resource: string;
    detail: Record<string, unknown> | null;
    client_ip: string | null;
    request_id: string | null;
  }[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface SettingsResponse {
  app_env: string;
  policy_mode: string;
  model: {
    model_tag: string;
    model_quantization: string;
    analysis_enabled: boolean;
    policy_mode: string;
  };
  ollama_base_url: string;
  retention_days: number;
  redaction: {
    enabled: boolean;
    ip_mode: string;
    email_mode: string;
    secret_patterns: boolean;
  };
  worker: {
    loop_enabled: boolean;
    interval_seconds: number;
    concurrency: number;
    batch_size: number;
  };
  remediation: {
    enabled: boolean;
    policy_mode: string;
    approval_ttl_minutes: number;
    rate_limit_per_hour: number;
    allow_blocked_actions: boolean;
    allow_self_approval: boolean;
    executor_timeout_seconds: number;
  };
  notifications: { enabled: boolean; roadmap_note: string };
}

// --- Correlations (Faz 06) ---------------------------------------------------

/** Kural çıktısı: LLM alanı BİLİNÇLİ OLARAK YOKTUR (analyses ayrı tabloda). */
export interface CorrelationEvidence {
  group_fields?: string[];
  group_value?: Record<string, string>;
  agent_names?: string[];
  src_ips?: string[];
  matched_rule_ids?: string[];
  alert_ids?: string[];
  first_alert_ids?: string[];
  then_alert_ids?: string[];
  [key: string]: unknown;
}

export interface CorrelationListItem {
  id: string;
  rule_key: string;
  rule_name: string;
  rule_version: number;
  window_start: string;
  window_end: string;
  event_count: number;
  max_rule_level: number;
  hit_count: number;
  first_hit_at: string;
  last_hit_at: string;
  evidence: CorrelationEvidence;
}

export interface CorrelationLinkedEvent {
  id: string;
  timestamp: string;
  alert_id: string;
  rule_id: string;
  rule_level: number;
  rule_description: string;
  agent_name: string | null;
  src_ip: string | null;
  analysis: AnalysisSummary | null; // LLM yorumu ayrı nesne
}

export interface CorrelationDetail extends CorrelationListItem {
  created_at: string;
  events: CorrelationLinkedEvent[];
}

export interface CorrelationListResponse {
  items: CorrelationListItem[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface CorrelationRuleItem {
  key: string;
  name: string;
  description: string;
  version: number;
  kind: string;
  params: {
    kind: string;
    window_seconds: number;
    threshold?: number;
    group_by: string[];
    match_rule_ids?: string[];
    match_rule_groups?: string[];
    match_min_level?: number;
    then_rule_ids?: string[];
    then_rule_groups?: string[];
    [key: string]: unknown;
  };
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CorrelationRuleListResponse {
  items: CorrelationRuleItem[];
}

export interface CorrelationRuleUpdateResponse {
  key: string;
  enabled: boolean;
  result: "updated" | "unchanged";
}

// --- Remediation (Faz 07) -----------------------------------------------------
//
// "Model eylemi doğrudan başlatamaz" (phases/07): öneri yalnızca kimlikli
// insan tarafından yapılır; yürütme daima SİMÜLASYON (simulated=true).

export interface RemediationCatalogItem {
  action_type: string;
  title: string;
  description: string;
  risk_level: "low" | "medium" | "high";
  default_blocked: boolean;
  enabled: boolean;
  target_scope: string;
  param_schema: Record<string, unknown>;
  risk_explanation: string;
  rollback_note: string;
  blocked_detail: string;
}

export interface RemediationCatalogResponse {
  items: RemediationCatalogItem[];
  policy_mode: string;
  remediation_enabled: boolean;
  allow_blocked_actions: boolean;
  approval_ttl_minutes: number;
  rate_limit_per_hour: number;
}

export interface RemediationCatalogUpdateResponse {
  action_type: string;
  enabled: boolean;
  result: "updated" | "unchanged";
}

export interface RemediationPolicyCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface RemediationActionItem {
  id: string;
  action_type: string;
  action_title: string;
  risk_level: "low" | "medium" | "high";
  status: "proposed" | "approved" | "rejected" | "expired" | "executed" | "failed";
  requested_by_username: string;
  approved_by_username: string | null;
  justification: string;
  created_at: string;
  approved_at: string | null;
  executed_at: string | null;
}

export interface RemediationActionDetail extends RemediationActionItem {
  params: Record<string, unknown>;
  evidence: RemediationEvidence;
  policy_decision: { allowed?: boolean; checks?: RemediationPolicyCheck[] };
  rejected_by_username: string | null;
  rejected_reason: string | null;
  rejected_at: string | null;
  execution_count: number;
  execution_result: {
    success?: boolean;
    simulated?: boolean;
    duration_ms?: number;
    output?: Record<string, unknown>;
  } | null;
  execution_error: string | null;
  updated_at: string;
}

/** Kanıt paketi (sunucu üretimi; alanlar build_evidence sözleşmesiyle aynı). */
export interface RemediationEvidence {
  event_ids?: string[];
  alert_ids?: string[];
  rule_ids?: string[];
  agent_ids?: string[];
  agent_names?: string[];
  src_ips?: string[];
  max_rule_level?: number;
  window_start?: string;
  window_end?: string;
  correlation_id?: string | null;
  risk_level?: string;
  risk_explanation?: string;
  rollback_note?: string;
  policy_mode?: string;
  built_at?: string;
  [key: string]: unknown;
}

export interface RemediationActionListResponse {
  items: RemediationActionDetail[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface RemediationCreateResponse {
  created: boolean;
  action: RemediationActionDetail;
}

export interface RemediationActionResponse {
  action: RemediationActionDetail;
  replayed: boolean;
}
