/** Korelasyon sayfaları testleri (Faz 06): kural çıktısı ↔ AI ayrımı, durumlar. */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import CorrelationsPage from "@/app/correlations/page";
import CorrelationDetailPage from "@/app/correlations/[id]/page";

const fetchMock = vi.fn();
global.fetch = fetchMock as unknown as typeof fetch;

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => "/correlations",
  useParams: () => ({ id: "test-id" }),
}));

const LIST_ITEM = {
  id: "11111111-1111-1111-1111-111111111111",
  rule_key: "failed_login_burst",
  rule_name: "Başarısız giriş patlaması",
  rule_version: 1,
  window_start: "2026-10-26T09:58:00Z",
  window_end: "2026-10-26T10:00:00Z",
  event_count: 6,
  max_rule_level: 10,
  hit_count: 2,
  first_hit_at: "2026-10-26T10:00:05Z",
  last_hit_at: "2026-10-26T10:00:35Z",
  evidence: {
    group_fields: ["agent_id"],
    group_value: { agent_id: "102" },
    agent_names: ["web-server-02"],
    src_ips: ["203.0.113.50"],
    matched_rule_ids: ["5710"],
    alert_ids: ["1792970000.200001"],
  },
};

const RULES = {
  items: [
    {
      key: "failed_login_burst",
      name: "Başarısız giriş patlaması",
      description: "sentetik",
      version: 1,
      kind: "burst",
      params: {
        kind: "burst",
        window_seconds: 300,
        threshold: 5,
        group_by: ["agent_id"],
        match_rule_groups: ["authentication_failed"],
      },
      enabled: true,
      created_at: "2026-10-26T00:00:00Z",
      updated_at: "2026-10-26T00:00:00Z",
    },
  ],
};

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
  return render(
    <QueryClientProvider client={client}>{ui}</QueryClientProvider>,
  );
}

describe("CorrelationsPage (liste)", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    window.localStorage.setItem("ajant.access_token", "test-access");
    window.localStorage.setItem("ajant.refresh_token", "test-refresh");
  });

  it("boş listede dürüst boş durum gösterilir ve kural çıktısı notu görünür", async () => {
    fetchMock.mockImplementation((url: string) => {
      if (String(url).includes("/correlation-rules")) return jsonOk(RULES);
      if (String(url).includes("/correlations")) {
        return jsonOk({ items: [], total: 0, page: 1, page_size: 25, pages: 0 });
      }
      if (String(url).includes("/auth/me")) {
        return jsonOk({ id: "u1", username: "admin", role: "admin" });
      }
      return jsonOk({});
    });
    renderWithClient(<CorrelationsPage />);
    await waitFor(() => {
      expect(screen.getByText("Korelasyon tespiti yok")).toBeInTheDocument();
    });
    expect(screen.getByText(/AI değerlendirmesi içermez/)).toBeInTheDocument();
  });

  it("tespit satırı kural adı+sürüm+kanıtı gösterir; LLM rozeti GÖSTERMEZ", async () => {
    fetchMock.mockImplementation((url: string) => {
      if (String(url).includes("/correlation-rules")) return jsonOk(RULES);
      if (String(url).includes("/correlations")) {
        return jsonOk({
          items: [LIST_ITEM],
          total: 1,
          page: 1,
          page_size: 25,
          pages: 1,
        });
      }
      if (String(url).includes("/auth/me")) {
        return jsonOk({ id: "u1", username: "admin", role: "admin" });
      }
      return jsonOk({});
    });
    renderWithClient(<CorrelationsPage />);
    await waitFor(() => {
      // Kural adı hem filtre seçeneğinde hem tablo satırında görünür:
      expect(screen.getAllByText("Başarısız giriş patlaması").length).toBeGreaterThan(1);
    });
    const row = screen
      .getAllByText("Başarısız giriş patlaması")
      .map((el) => el.closest("tr"))
      .find((r) => r !== null);
    expect(row).toBeDefined();
    expect(within(row as HTMLElement).getByText(/v1/)).toBeInTheDocument();
    expect(within(row as HTMLElement).getByText(/web-server-02/)).toBeInTheDocument();
    // Kural çıktısı listesinde AI rozetleri YOK (ayrım sözleşmesi):
    expect(within(row as HTMLElement).queryByText(/AI:/)).toBeNull();
  });
});

describe("CorrelationDetailPage (detay)", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    window.localStorage.setItem("ajant.access_token", "test-access");
    window.localStorage.setItem("ajant.refresh_token", "test-refresh");
  });

  it("kural kartı 'kural motoru çıktısı' etiketi taşır; AI rozetleri olay satırlarında AYRI görünür", async () => {
    const detail = {
      ...LIST_ITEM,
      created_at: "2026-10-26T10:00:05Z",
      events: [
        {
          id: "e1",
          timestamp: "2026-10-26T09:58:00Z",
          alert_id: "1792970000.200001",
          rule_id: "5710",
          rule_level: 10,
          rule_description: "sshd: Brute force trying to get access to the system.",
          agent_name: "web-server-02",
          src_ip: "203.0.113.50",
          analysis: {
            status: "completed",
            ai_assessment: "malicious",
            confidence: 0.9,
            requires_human_review: true,
            model_tag: "qwen3:4b",
            finished_at: "2026-10-26T10:01:00Z",
          },
        },
        {
          id: "e2",
          timestamp: "2026-10-26T09:58:24Z",
          alert_id: "1792970000.200002",
          rule_id: "5710",
          rule_level: 10,
          rule_description: "sshd: Brute force trying to get access to the system.",
          agent_name: "web-server-02",
          src_ip: "203.0.113.50",
          analysis: null,
        },
      ],
    };
    fetchMock.mockImplementation((url: string) => {
      if (String(url).includes("/correlations/test-id")) return jsonOk(detail);
      if (String(url).includes("/auth/me")) {
        return jsonOk({ id: "u1", username: "admin", role: "admin" });
      }
      return jsonOk({});
    });
    renderWithClient(<CorrelationDetailPage />);
    await waitFor(() => {
      expect(screen.getByText("kural motoru çıktısı")).toBeInTheDocument();
    });
    // LLM yorumu yalnızca analizli olayda, AYRI rozet olarak:
    expect(screen.getByText("AI: kötücül · %90")).toBeInTheDocument();
    expect(screen.getByText("analiz yok")).toBeInTheDocument();
    // Korelasyon gövdesinde (kural kartında) ai_assessment metni YOK:
    const ruleCard = screen
      .getByText("kural motoru çıktısı")
      .closest("div.rounded-lg");
    expect(ruleCard).not.toBeNull();
    expect(within(ruleCard as HTMLElement).queryByText(/AI:/)).toBeNull();
  });
});
