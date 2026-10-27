/** Olay listesi ortak satır bileşeni + AI rozet yardımcıları (Faz 05). */

import { Badge } from "@/components/ui/badge";
import type { EventListItem } from "@/lib/types";

/** Wazuh rule_level → görsel ton (ORİJİNAL severity; AI değeri DEĞİL). */
export function levelTone(level: number): "ok" | "warn" | "danger" | "neutral" {
  if (level >= 12) return "danger";
  if (level >= 7) return "warn";
  if (level >= 4) return "ok";
  return "neutral";
}

/** Model değerlendirmesi → görsel ton (ayrı renk ailesi: mor tonları AI'ya ait). */
export function assessmentBadge(assessment: string | null): {
  tone: "ok" | "warn" | "danger" | "neutral";
  label: string;
} {
  switch (assessment) {
    case "benign":
      return { tone: "ok", label: "zararsız" };
    case "suspicious":
      return { tone: "warn", label: "şüpheli" };
    case "malicious":
      return { tone: "danger", label: "kötücül" };
    case "unknown":
      return { tone: "neutral", label: "belirsiz" };
    default:
      return { tone: "neutral", label: "—" };
  }
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  try {
    return new Intl.DateTimeFormat("tr-TR", {
      dateStyle: "short",
      timeStyle: "medium",
      timeZone: "UTC",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

/** Liste/detayda AI durum rozeti: analysis_failed ayrı gösterilir. */
export function AiStatusBadge({ analysis }: { analysis: EventListItem["analysis"] }) {
  if (!analysis) {
    return <Badge tone="neutral">analiz yok</Badge>;
  }
  if (analysis.status === "analysis_failed") {
    return <Badge tone="danger">AI: analiz başarısız</Badge>;
  }
  const badge = assessmentBadge(analysis.ai_assessment);
  return (
    <Badge tone={badge.tone}>
      AI: {badge.label}
      {analysis.confidence !== null
        ? ` · %${Math.round(analysis.confidence * 100)}`
        : ""}
    </Badge>
  );
}
