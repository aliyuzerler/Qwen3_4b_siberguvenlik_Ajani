"use client";

/** Sunucular/agent'lar (Faz 05): olaylardan türetilen envanter. */

import { useQuery } from "@tanstack/react-query";

import { formatDateTime } from "@/components/event-bits";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import { PanelShell } from "@/components/panel-shell";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { AgentListResponse } from "@/lib/types";

export default function AgentsPage() {
  const agents = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.get<AgentListResponse>("/api/v1/agents"),
    refetchInterval: 60_000,
  });

  return (
    <PanelShell>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-lg font-semibold text-slate-100">Sunucular / Agent&apos;lar</h1>
        {agents.data ? (
          <span className="text-xs text-slate-500">{agents.data.total} kayıt</span>
        ) : null}
      </div>

      <p className="mb-4 rounded-lg border border-slate-800 bg-slate-900/40 px-4 py-2 text-xs text-slate-500">
        Not: liste, panelin gördüğü olaylardan türetilen envanterdir; canlı
        bağlantı/health durumu Genel Bakış ekranındaki Wazuh bileşen kartında gösterilir.
      </p>

      {agents.isLoading ? <LoadingState /> : null}
      {agents.isError ? (
        <ErrorState
          message={agents.error instanceof Error ? agents.error.message : "bilinmeyen hata"}
          onRetry={() => void agents.refetch()}
        />
      ) : null}

      {agents.data ? (
        agents.data.items.length === 0 ? (
          <EmptyState
            title="Henüz agent kaydı yok"
            hint="Wazuh olayları geldiğinde agent envanteri otomatik oluşur."
          />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Agent</TH>
                <TH>Agent ID</TH>
                <TH>Manager</TH>
                <TH>Olay sayısı</TH>
                <TH>İlk görülme (UTC)</TH>
                <TH>Son görülme (UTC)</TH>
              </TR>
            </THead>
            <TBody>
              {agents.data.items.map((agent, index) => (
                <TR key={`${agent.agent_id ?? "none"}-${index}`}>
                  <TD className="font-medium text-slate-200">{agent.agent_name ?? "(agent yok)"}</TD>
                  <TD className="font-mono text-xs">{agent.agent_id ?? "—"}</TD>
                  <TD>{agent.manager ?? "—"}</TD>
                  <TD>{agent.event_count}</TD>
                  <TD className="whitespace-nowrap text-xs">{formatDateTime(agent.first_seen)}</TD>
                  <TD className="whitespace-nowrap text-xs">{formatDateTime(agent.last_seen)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )
      ) : null}
    </PanelShell>
  );
}
