"use client";

/**
 * Korelasyon detayı (Faz 06).
 *
 * Görsel ayrım sözleşmesi (AGENTS.md §5):
 * - Üstte KURAL kartı: kural adı/sürümü, pencere, kanıt (grup, agent, IP,
 *   eşleşen Wazuh kural ID'leri, alert listesi). LLM alanı YOKTUR.
 * - Altta eşleşen olaylar: orijinal kanıt + her olayın KENDİ model kaydı
 *   ayrı "AI" rozetinde (mor aile) gösterilir; kural çıktısıyla karışmaz.
 */

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";

import { AiStatusBadge, formatDateTime, levelTone } from "@/components/event-bits";
import { ErrorState, ForbiddenState, LoadingState } from "@/components/states";
import { PanelShell } from "@/components/panel-shell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { ApiError, api } from "@/lib/api";
import type { CorrelationDetail } from "@/lib/types";

export default function CorrelationDetailPage() {
  const params = useParams<{ id: string }>();
  const correlation = useQuery({
    queryKey: ["correlation", params.id],
    queryFn: () =>
      api.get<CorrelationDetail>(`/api/v1/correlations/${params.id}`),
    retry: false,
  });

  if (correlation.isLoading) {
    return (
      <PanelShell>
        <LoadingState />
      </PanelShell>
    );
  }
  if (correlation.error instanceof ApiError && correlation.error.status === 401) {
    return (
      <PanelShell>
        <ErrorState message="Oturum doğrulanamadı." />
      </PanelShell>
    );
  }
  if (
    correlation.error instanceof ApiError &&
    (correlation.error.status === 403 || correlation.error.status === 404)
  ) {
    return (
      <PanelShell>
        <ForbiddenState />
      </PanelShell>
    );
  }
  if (correlation.isError || !correlation.data) {
    return (
      <PanelShell>
        <ErrorState
          message={
            correlation.error instanceof Error ? correlation.error.message : ""
          }
          onRetry={() => void correlation.refetch()}
        />
      </PanelShell>
    );
  }

  const item = correlation.data;
  const evidence = item.evidence;

  return (
    <PanelShell>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-lg font-semibold text-slate-100">
          Korelasyon Detayı
        </h1>
        <Link href="/correlations">
          <Button variant="outline">
            ← Listeye dön
          </Button>
        </Link>
      </div>

      {/* --- KURAL kartı (kural çıktısı; LLM yok) --- */}
      <Card className="mb-6 border-slate-800 bg-slate-900/40">
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2 text-base">
            <span className="text-slate-100">{item.rule_name}</span>
            <span className="rounded border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
              {item.rule_key} · v{item.rule_version}
            </span>
            <span className="rounded border border-sky-800 bg-sky-950/40 px-1.5 py-0.5 text-[10px] text-sky-300">
              kural motoru çıktısı
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="grid grid-cols-2 gap-3 text-xs text-slate-400 sm:grid-cols-4">
            <div>
              <div className="text-slate-500">Pencere başlangıcı (UTC)</div>
              <div className="text-slate-200">{formatDateTime(item.window_start)}</div>
            </div>
            <div>
              <div className="text-slate-500">Pencere sonu (UTC)</div>
              <div className="text-slate-200">{formatDateTime(item.window_end)}</div>
            </div>
            <div>
              <div className="text-slate-500">Eşleşen olay</div>
              <div className="text-slate-200">{item.event_count}</div>
            </div>
            <div>
              <div className="text-slate-500">Tekrar (hit)</div>
              <div className="text-slate-200">{item.hit_count} kez</div>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
            <div>
              <div className="mb-1 text-slate-500">Grup (ilişki anahtarı)</div>
              <div className="rounded border border-slate-800 bg-slate-950/60 p-2 font-mono text-[11px] text-slate-300">
                {Object.entries(evidence.group_value ?? {})
                  .map(([key, value]) => `${key}=${value}`)
                  .join(" · ") || "—"}
              </div>
            </div>
            <div>
              <div className="mb-1 text-slate-500">Eşleşen Wazuh kural ID'leri</div>
              <div className="flex flex-wrap gap-1">
                {(evidence.matched_rule_ids ?? []).map((ruleId) => (
                  <span
                    key={ruleId}
                    className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] text-slate-300"
                  >
                    rule {ruleId}
                  </span>
                ))}
                {(evidence.matched_rule_ids ?? []).length === 0 ? "—" : null}
              </div>
            </div>
          </div>

          <div>
            <div className="mb-1 text-xs text-slate-500">Kanıt (alert ID'leri, zaman sırasıyla)</div>
            <div className="flex flex-wrap gap-1">
              {(evidence.alert_ids ?? []).map((alertId) => (
                <span
                  key={alertId}
                  className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] text-slate-400"
                >
                  {alertId}
                </span>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* --- Eşleşen olaylar (orijinal kanıt + AYRI AI rozetleri) --- */}
      <h2 className="mb-2 text-sm font-semibold text-slate-200">
        Eşleşen olaylar ({item.events.length})
      </h2>
      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <Table>
          <THead>
            <TR>
              <TH>Zaman (UTC)</TH>
              <TH>Alert ID</TH>
              <TH>Kural</TH>
              <TH>Seviye</TH>
              <TH>Agent</TH>
              <TH>Kaynak IP</TH>
              <TH>AI değerlendirmesi (ayrı)</TH>
            </TR>
          </THead>
          <TBody>
            {item.events.map((event) => (
              <TR key={event.id}>
                <TD className="whitespace-nowrap text-xs text-slate-400">
                  {formatDateTime(event.timestamp)}
                </TD>
                <TD className="font-mono text-[11px] text-slate-300">
                  {event.alert_id}
                </TD>
                <TD className="max-w-64 text-xs text-slate-300">
                  <div className="truncate">{event.rule_description}</div>
                  <div className="text-[11px] text-slate-500">rule {event.rule_id}</div>
                </TD>
                <TD className="text-sm text-slate-300">{event.rule_level}</TD>
                <TD className="text-xs text-slate-400">{event.agent_name ?? "—"}</TD>
                <TD className="font-mono text-[11px] text-slate-400">
                  {event.src_ip ?? "—"}
                </TD>
                <TD>
                  {/* LLM yorumu olaya ait ayrı nesne; kural kartıyla karışmaz */}
                  <AiStatusBadge analysis={event.analysis} />
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </div>
      <p className="mt-3 text-[11px] text-slate-500">
        Olay satırlarındaki mor rozetler model (Qwen3 4B) kayıtlarıdır; kural
        tespitinden bağımsızdır. Analizi olmayan olaylar dürüstçe "analiz yok"
        gösterilir. Detay için Olaylar bölümünde alert ID ile arayın.
      </p>
    </PanelShell>
  );
}
