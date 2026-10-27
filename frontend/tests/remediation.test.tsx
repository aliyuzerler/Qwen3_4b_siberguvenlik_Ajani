/** Müdahale sayfaları testleri (Faz 07): allowlist, simülasyon rozeti, görev ayrımı. */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import RemediationPage from "@/app/remediation/page";
import RemediationDetailPage from "@/app/remediation/[id]/page";
import { AuthProvider } from "@/lib/auth";

const fetchMock = vi.fn();
global.fetch = fetchMock as unknown as typeof fetch;

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => "/remediation",
  useParams: () => ({ id: "test-id" }),
}));

function jsonOk(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function renderWithClient(ui: React.ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  // AuthProvider dahil: detay sayfası kullanıcı kimliğiyle görev ayrımı
  // uyarısını koşullar (useAuth context'ten okur).
  return render(
    <QueryClientProvider client={client}>
      <AuthProvider>{ui}</AuthProvider>
    </QueryClientProvider>,
  );
}

const CATALOG = {
  items: [
    {
      action_type: "notify_admin",
      title: "Yöneticiyi bilgilendir",
      description: "sistem değişikliği yapmaz",
      risk_level: "low",
      default_blocked: false,
      enabled: true,
      target_scope: "any_event",
      param_schema: {},
      risk_explanation: "Düşük risk: kayıt dışında hiçbir değişiklik yapılmaz.",
      rollback_note: "Geri alma gerekmez.",
      blocked_detail: "",
    },
    {
      action_type: "block_src_ip",
      title: "Kaynak IP'yi engelle (firewall)",
      description: "firewall kuralı",
      risk_level: "high",
      default_blocked: true,
      enabled: false,
      target_scope: "src_ip",
      param_schema: {},
      risk_explanation: "YÜKSEK risk: kritik erişim kesilebilir.",
      rollback_note: "Kural ters adımla kaldırılır.",
      blocked_detail: "İki bağımsız kapı gerekir.",
    },
  ],
  policy_mode: "observe_only",
  remediation_enabled: true,
  allow_blocked_actions: false,
  approval_ttl_minutes: 60,
  rate_limit_per_hour: 20,
};

const ACTION_DETAIL = {
  id: "22222222-2222-2222-2222-222222222222",
  action_type: "restart_wazuh_agent",
  action_title: "Wazuh ajanını yeniden başlat",
  risk_level: "medium",
  status: "proposed",
  requested_by_username: "analyst",
  approved_by_username: null,
  justification: "Telemetri akışı kesilmişti; ajan restart gerekli.",
  created_at: "2026-10-27T09:00:00Z",
  approved_at: null,
  executed_at: null,
  params: { agent_id: "001" },
  evidence: {
    event_ids: ["e1"],
    alert_ids: ["100.1"],
    agent_names: ["web-server-01"],
    src_ips: ["203.0.113.7"],
    max_rule_level: 10,
    risk_explanation: "Orta risk metni.",
    rollback_note: "Rollback metni.",
  },
  policy_decision: {
    allowed: true,
    checks: [
      { name: "action_in_allowlist", passed: true, detail: "restart_wazuh_agent" },
      { name: "target_scope", passed: true, detail: "agent_id VAR" },
    ],
  },
  rejected_by_username: null,
  rejected_reason: null,
  rejected_at: null,
  execution_count: 0,
  execution_result: null,
  execution_error: null,
  updated_at: "2026-10-27T09:00:00Z",
};

describe("RemediationPage (liste + katalog)", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    window.localStorage.setItem("ajant.access_token", "test-access");
    window.localStorage.setItem("ajant.refresh_token", "test-refresh");
  });

  it("allowlist kataloğunda default_blocked rozeti görünür; kural: serbest komut yoktur notu", async () => {
    fetchMock.mockImplementation((url: string) => {
      if (String(url).includes("/remediation/catalog")) return jsonOk(CATALOG);
      if (String(url).includes("/remediation/actions")) {
        return jsonOk({ items: [], total: 0, page: 1, page_size: 20, pages: 0 });
      }
      if (String(url).includes("/auth/me")) {
        return jsonOk({ id: "u1", username: "admin", role: "admin" });
      }
      return jsonOk({});
    });
    renderWithClient(<RemediationPage />);
    await waitFor(() => {
      expect(screen.getByText("Kaynak IP'yi engelle (firewall)")).toBeInTheDocument();
    });
    expect(screen.getAllByText("varsayılan engelli").length).toBeGreaterThan(0);
    expect(screen.getByText(/Model eylem BAŞLATAMAZ/)).toBeInTheDocument();
  });

  it("boş öneri listesi dürüst boş durum gösterir", async () => {
    fetchMock.mockImplementation((url: string) => {
      if (String(url).includes("/remediation/catalog")) return jsonOk(CATALOG);
      if (String(url).includes("/remediation/actions")) {
        return jsonOk({ items: [], total: 0, page: 1, page_size: 20, pages: 0 });
      }
      if (String(url).includes("/auth/me")) {
        return jsonOk({ id: "u1", username: "admin", role: "admin" });
      }
      return jsonOk({});
    });
    renderWithClient(<RemediationPage />);
    await waitFor(() => {
      expect(screen.getByText("Öneri yok")).toBeInTheDocument();
    });
  });
});

describe("RemediationDetailPage (detay)", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    window.localStorage.setItem("ajant.access_token", "test-access");
    window.localStorage.setItem("ajant.refresh_token", "test-refresh");
  });

  it("kanıt paketi + politika izi gösterilir; görev ayrımı uyarısı görünür", async () => {
    fetchMock.mockImplementation((url: string) => {
      if (String(url).includes("/remediation/actions/test-id")) return jsonOk(ACTION_DETAIL);
      if (String(url).includes("/auth/me")) {
        // öneren admin olarak giriş yaptı → görev ayrımı uyarısı
        return jsonOk({ id: "u1", username: "analyst", role: "admin" });
      }
      return jsonOk({});
    });
    renderWithClient(<RemediationDetailPage />);
    await waitFor(() => {
      expect(screen.getByText("Kanıt paketi")).toBeInTheDocument();
    });
    expect(screen.getByText("100.1")).toBeInTheDocument();
    expect(screen.getByText("allowlist üyeliği")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText(/Görev ayrımı/)).toBeInTheDocument();
    });
    // SİMÜLASYON rozeti yalnızca yürütüldüğünde görünür:
    expect(screen.queryByText(/SİMÜLASYON/)).toBeNull();
  });

  it("yürütülmüş aksiyonda SİMÜLASYON rozeti dürüstçe görünür", async () => {
    fetchMock.mockImplementation((url: string) => {
      if (String(url).includes("/remediation/actions/test-id")) {
        return jsonOk({
          ...ACTION_DETAIL,
          status: "executed",
          approved_by_username: "admin2",
          executed_at: "2026-10-27T09:10:00Z",
          execution_count: 1,
          execution_result: {
            success: true,
            simulated: true,
            duration_ms: 3,
            output: { plan: "gerçek ortamda restart gönderilecektir", mode: "dry_run" },
          },
        });
      }
      if (String(url).includes("/auth/me")) {
        return jsonOk({ id: "u1", username: "admin2", role: "admin" });
      }
      return jsonOk({});
    });
    renderWithClient(<RemediationDetailPage />);
    await waitFor(() => {
      expect(screen.getByText(/SİMÜLASYON — sistem değişikliği yapılmadı/)).toBeInTheDocument();
    });
    expect(screen.getByText("simulated: true")).toBeInTheDocument();
    expect(screen.getByText(/restart gönderilecektir/)).toBeInTheDocument();
  });
});
