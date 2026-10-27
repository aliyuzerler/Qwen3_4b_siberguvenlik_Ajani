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
  notifications: { enabled: boolean; roadmap_note: string };
}
