/**
 * XSS güvenlik testleri (Faz 05).
 *
 * Sözleşme: panelde zararlı içerikli log/model metinleri METİN olarak
 * gösterilir; script/img etiketleri DOM'a Eleman olarak SOKULMAZ.
 * React'in otomatik kaçışı buna güvence verir — test bu güvenceyi kilitler.
 * Ek olarak yapısal kural: dangerouslySetInnerHTML tüm kaynak ağaçta yasak.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AiStatusBadge } from "@/components/event-bits";
import type { EventListItem } from "@/lib/types";

const XSS_PAYLOAD = '<script>alert("xss")</script> 🚨 <img src=x onerror=alert(1)>';

function allSourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...allSourceFiles(full));
    } else if (/\.(tsx?|mjs|ts)$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

describe("XSS güvenliği (yapısal)", () => {
  it("kaynak ağaçta dangerouslySetInnerHTML PROP KULLANIMI yoktur", () => {
    const srcDir = join(__dirname, "..", "src");
    // Yalnızca GERÇEK JSX prop kullanımı denetlenir (docstring/belirtme değil):
    const offenders = allSourceFiles(srcDir).filter((file) =>
      /dangerouslySetInnerHTML\s*=/.test(readFileSync(file, "utf8")),
    );
    expect(offenders).toEqual([]);
  });

  it("AI özet metni script etiketini ELEMENT olarak oluşturmaz", () => {
    const { container } = render(
      <div>
        <p>{XSS_PAYLOAD}</p>
      </div>,
    );
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    // Metin tam olarak korunur (kaçış React'in işi; test ham metnin
    // DOM'a eleman olarak girmediğini ve metin içerikte korunduğunu doğrular)
    expect(container.textContent).toContain('<script>alert("xss")</script>');
  });
});

describe("AI durum rozeti", () => {
  const base: EventListItem["analysis"] = {
    status: "completed",
    ai_assessment: "malicious",
    confidence: 0.81,
    requires_human_review: true,
    model_tag: "qwen3:4b",
    finished_at: new Date().toISOString(),
  };

  it("completed + malicious → kırmızı ton AI rozeti", () => {
    render(<AiStatusBadge analysis={base} />);
    const badge = screen.getByText(/AI: kötücül/);
    expect(badge).toBeInTheDocument();
  });

  it("analysis_failed → 'analiz başarısız' rozeti (değer gösterilmez)", () => {
    render(
      <AiStatusBadge
        analysis={{ ...base, status: "analysis_failed", ai_assessment: null }}
      />,
    );
    expect(screen.getByText("AI: analiz başarısız")).toBeInTheDocument();
  });

  it("analysis null → 'analiz yok' rozeti", () => {
    render(<AiStatusBadge analysis={null} />);
    expect(screen.getByText("analiz yok")).toBeInTheDocument();
  });
});
