/** Durum bileşenleri + liste etkileşim testleri (Faz 05). */
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AiStatusBadge, assessmentBadge, levelTone } from "@/components/event-bits";
import { EmptyState, ErrorState, ForbiddenState, LoadingState } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

describe("Durum bileşenleri", () => {
  it("LoadingState role=status ve erişilebilir etiket taşır", () => {
    render(<LoadingState label="Veriler yükleniyor…" />);
    expect(screen.getByRole("status")).toHaveTextContent("Veriler yükleniyor…");
  });

  it("EmptyState başlık ve ipucu gösterir", () => {
    render(<EmptyState title="Olay yok" hint="Kaynağı kontrol edin" />);
    expect(screen.getByText("Olay yok")).toBeInTheDocument();
    expect(screen.getByText("Kaynağı kontrol edin")).toBeInTheDocument();
  });

  it("ErrorState role=alert + yeniden dene çalışır", async () => {
    const onRetry = vi.fn();
    const { getByRole } = render(
      <ErrorState message="bağlantı kesildi" onRetry={onRetry} />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("bağlantı kesildi");
    getByRole("button", { name: "Yeniden dene" }).click();
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it("ForbiddenState yetki mesajı verir", () => {
    render(<ForbiddenState />);
    expect(screen.getByRole("alert")).toHaveTextContent("Erişim yetkiniz yok");
  });
});

describe("Görsel ayrım yardımcıları", () => {
  it("rule_level seviyeleri doğru tona eşlenir (orijinal Wazuh severity)", () => {
    expect(levelTone(15)).toBe("danger");
    expect(levelTone(8)).toBe("warn");
    expect(levelTone(5)).toBe("ok");
    expect(levelTone(0)).toBe("neutral");
  });

  it("assessment etiketleri Türkçe ve ayrı ton ailesindedir", () => {
    expect(assessmentBadge("benign").label).toBe("zararsız");
    expect(assessmentBadge("suspicious").label).toBe("şüpheli");
    expect(assessmentBadge("malicious").label).toBe("kötücül");
    expect(assessmentBadge(null).label).toBe("—");
  });

  it("Badge tone sınıfları AI (mor) ailesini taşır", () => {
    const { container } = render(<Badge tone="ai">AI</Badge>);
    expect(container.firstChild).toHaveTextContent("AI");
  });
});
