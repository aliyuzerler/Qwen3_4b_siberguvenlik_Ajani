"use client";

/** Olay listesi (Faz 05): filtreler + sayfalama + durum yönetimi. */

import { useQuery, keepPreviousData } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import { AiStatusBadge, formatDateTime, levelTone } from "@/components/event-bits";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import { PanelShell } from "@/components/panel-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { EventListResponse } from "@/lib/types";

export default function EventsPage() {
  const [page, setPage] = useState(1);
  const [assessment, setAssessment] = useState("");
  const [ruleLevelMin, setRuleLevelMin] = useState("");
  const [agentName, setAgentName] = useState("");
  const [q, setQ] = useState("");

  const events = useQuery({
    queryKey: ["events", { page, assessment, ruleLevelMin, agentName, q }],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(page), page_size: "25" });
      if (assessment) params.set("assessment", assessment);
      if (ruleLevelMin) params.set("rule_level_min", ruleLevelMin);
      if (agentName) params.set("agent_name", agentName);
      if (q) params.set("q", q);
      return api.get<EventListResponse>(`/api/v1/events?${params.toString()}`);
    },
    placeholderData: keepPreviousData,
  });

  return (
    <PanelShell>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-lg font-semibold text-slate-100">Olaylar</h1>
        {events.data ? (
          <span className="text-xs text-slate-500">{events.data.total} olay</span>
        ) : null}
      </div>

      {/* Filtreler */}
      <form
        aria-label="Olay filtreleri"
        className="mb-4 grid grid-cols-1 gap-3 rounded-lg border border-slate-800 bg-slate-900/40 p-4 sm:grid-cols-4"
        onSubmit={(e) => {
          e.preventDefault();
          setPage(1);
          void events.refetch();
        }}
      >
        <div>
          <Label htmlFor="f-assessment">AI durumu</Label>
          <Select
            id="f-assessment"
            value={assessment}
            onChange={(e) => {
              setAssessment(e.target.value);
              setPage(1);
            }}
          >
            <option value="">Tümü</option>
            <option value="completed">Analiz tamamlandı</option>
            <option value="analysis_failed">Analiz başarısız</option>
            <option value="none">Analiz yok</option>
          </Select>
        </div>
        <div>
          <Label htmlFor="f-level">En düşük seviye</Label>
          <Select
            id="f-level"
            value={ruleLevelMin}
            onChange={(e) => {
              setRuleLevelMin(e.target.value);
              setPage(1);
            }}
          >
            <option value="">Tümü</option>
            {[7, 10, 12].map((level) => (
              <option key={level} value={level}>
                ≥ {level}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="f-agent">Agent adı</Label>
          <Input
            id="f-agent"
            value={agentName}
            onChange={(e) => {
              setAgentName(e.target.value);
              setPage(1);
            }}
            placeholder="örn. web-01"
          />
        </div>
        <div>
          <Label htmlFor="f-q">Arama</Label>
          <Input
            id="f-q"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setPage(1);
            }}
            placeholder="kural / agent / alert ID"
          />
        </div>
      </form>

      {events.isLoading ? <LoadingState label="Olaylar yükleniyor…" /> : null}
      {events.isError ? (
        <ErrorState
          message={events.error instanceof Error ? events.error.message : "bilinmeyen hata"}
          onRetry={() => void events.refetch()}
        />
      ) : null}

      {events.data ? (
        events.data.items.length === 0 ? (
          <EmptyState
            title="Bu filtrelerle olay bulunamadı"
            hint="Filtreleri temizleyin veya Wazuh kaynağının olay üretmesini bekleyin."
          />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH>Zaman (UTC)</TH>
                  <TH>Kaynak</TH>
                  <TH>Agent</TH>
                  <TH>Kural</TH>
                  <TH>Seviye</TH>
                  <TH>AI değerlendirmesi</TH>
                  <TH>Tekrar</TH>
                </TR>
              </THead>
              <TBody>
                {events.data.items.map((event) => (
                  <TR key={event.id}>
                    <TD className="whitespace-nowrap font-mono text-xs">
                      {formatDateTime(event.timestamp)}
                    </TD>
                    <TD className="text-xs text-slate-400">{event.source}</TD>
                    <TD>{event.agent_name ?? "—"}</TD>
                    <TD>
                      <Link href={`/events/${event.id}`} className="text-sky-400 hover:underline">
                        {event.rule_description}
                      </Link>
                      <div className="mt-0.5 text-[11px] text-slate-500">
                        kural {event.rule_id} · alert {event.alert_id}
                      </div>
                    </TD>
                    <TD>
                      <Badge tone={levelTone(event.rule_level)}>{event.rule_level}</Badge>
                    </TD>
                    <TD>
                      <AiStatusBadge analysis={event.analysis} />
                    </TD>
                    <TD className="text-xs text-slate-400">
                      {event.seen_count}×
                      {event.variant_count > 0 ? ` · ${event.variant_count} varyant` : ""}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>

            {/* Sayfalama */}
            <nav
              aria-label="Sayfalama"
              className="mt-4 flex items-center justify-between text-sm"
            >
              <Button
                variant="outline"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                ← Önceki
              </Button>
              <span className="text-xs text-slate-500">
                Sayfa {events.data.page} / {Math.max(1, events.data.pages)}
              </span>
              <Button
                variant="outline"
                disabled={page >= events.data.pages}
                onClick={() => setPage((p) => p + 1)}
              >
                Sonraki →
              </Button>
            </nav>
          </>
        )
      ) : null}
    </PanelShell>
  );
}
