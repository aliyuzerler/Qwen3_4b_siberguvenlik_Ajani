"use client";

/** Genel bakış (Faz 05): bileşen sağlığı, sayaçlar, son olaylar, model künyesi. */

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";

import { AiStatusBadge, formatDateTime, levelTone } from "@/components/event-bits";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import { PanelShell } from "@/components/panel-shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { OverviewResponse } from "@/lib/types";

const COMPONENT_LABELS: Record<string, string> = {
  database: "Veritabanı",
  wazuh: "Wazuh",
  ollama: "Ollama (Model)",
};

function StatusBadge({ status }: { status: string }) {
  const tone =
    status === "up" ? "ok" : status === "disabled" || status === "not_configured" ? "neutral" : "danger";
  const labels: Record<string, string> = {
    up: "çalışıyor",
    down: "erişilemiyor",
    disabled: "kapalı",
    not_configured: "yapılandırılmadı",
    model_missing: "model eksik",
  };
  return <Badge tone={tone}>{labels[status] ?? status}</Badge>;
}

export default function OverviewPage() {
  const overview = useQuery({
    queryKey: ["overview"],
    queryFn: () => api.get<OverviewResponse>("/api/v1/overview"),
    refetchInterval: 60_000,
  });

  return (
    <PanelShell>
      <h1 className="mb-4 text-lg font-semibold text-slate-100">Genel Bakış</h1>

      {overview.isLoading ? <LoadingState /> : null}
      {overview.isError ? (
        <ErrorState
          message={overview.error instanceof Error ? overview.error.message : "bilinmeyen hata"}
          onRetry={() => void overview.refetch()}
        />
      ) : null}

      {overview.data ? (
        <div className="space-y-6">
          {/* Bileşen sağlığı */}
          <section aria-labelledby="saglik-baslik">
            <h2 id="saglik-baslik" className="sr-only">
              Bileşen sağlığı
            </h2>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              {Object.entries(overview.data.components).map(([key, status]) => (
                <Card key={key}>
                  <CardHeader>
                    <CardTitle>{COMPONENT_LABELS[key] ?? key}</CardTitle>
                    <StatusBadge status={status} />
                  </CardHeader>
                </Card>
              ))}
            </div>
          </section>

          {/* Sayaçlar */}
          <section aria-labelledby="sayac-baslik" className="grid grid-cols-2 gap-4 sm:grid-cols-5">
            <h2 id="sayac-baslik" className="sr-only">
              Sayaçlar
            </h2>
            {[
              ["Toplam olay", overview.data.counts.total_events],
              ["Son 24 saat", overview.data.counts.events_24h],
              ["Tamamlanan analiz", overview.data.counts.analyses_completed],
              ["Başarısız analiz", overview.data.counts.analyses_failed],
              ["Bekleyen analiz", overview.data.counts.pending_analysis],
            ].map(([label, value]) => (
              <Card key={String(label)}>
                <CardContent>
                  <p className="text-2xl font-semibold text-slate-100">{String(value)}</p>
                  <p className="mt-1 text-xs text-slate-500">{label}</p>
                </CardContent>
              </Card>
            ))}
          </section>

          {/* Model + değerlendirme dağılımı */}
          <section className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Model</CardTitle>
                <Badge tone="info">{overview.data.model.policy_mode}</Badge>
              </CardHeader>
              <CardContent className="space-y-1">
                <p>
                  Model tag: <span className="font-mono text-slate-200">{overview.data.model.model_tag}</span>
                </p>
                <p>
                  Kuantizasyon:{" "}
                  <span className="font-mono text-slate-200">
                    {overview.data.model.model_quantization}
                  </span>
                </p>
                <p className="text-xs text-slate-500">
                  Analiz döngüsü: {overview.data.model.analysis_enabled ? "etkin" : "kapalı"}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Model değerlendirme dağılımı</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-2">
                <Badge tone="ok">zararsız: {overview.data.by_assessment.benign}</Badge>
                <Badge tone="warn">şüpheli: {overview.data.by_assessment.suspicious}</Badge>
                <Badge tone="danger">kötücül: {overview.data.by_assessment.malicious}</Badge>
                <Badge tone="neutral">belirsiz: {overview.data.by_assessment.unknown}</Badge>
              </CardContent>
            </Card>
          </section>

          {/* Son olaylar */}
          <section aria-labelledby="son-olaylar">
            <h2 id="son-olaylar" className="mb-3 text-sm font-semibold text-slate-200">
              Son olaylar
            </h2>
            {overview.data.recent.length === 0 ? (
              <EmptyState
                title="Henüz olay yok"
                hint="Wazuh kaynağı yapılandırıldığında olaylar burada listelenecektir."
              />
            ) : (
              <Table>
                <THead>
                  <TR>
                    <TH>Zaman (UTC)</TH>
                    <TH>Agent</TH>
                    <TH>Kural</TH>
                    <TH>Seviye</TH>
                    <TH>AI değerlendirmesi</TH>
                  </TR>
                </THead>
                <TBody>
                  {overview.data.recent.map((event) => (
                    <TR key={event.id}>
                      <TD className="whitespace-nowrap font-mono text-xs">
                        {formatDateTime(event.timestamp)}
                      </TD>
                      <TD>{event.agent_name ?? "—"}</TD>
                      <TD>
                        <Link
                          href={`/events/${event.id}`}
                          className="text-sky-400 hover:underline"
                        >
                          {event.rule_description}
                        </Link>
                      </TD>
                      <TD>
                        <Badge tone={levelTone(event.rule_level)}>{event.rule_level}</Badge>
                      </TD>
                      <TD>
                        <AiStatusBadge analysis={event.analysis} />
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </section>
        </div>
      ) : null}
    </PanelShell>
  );
}
