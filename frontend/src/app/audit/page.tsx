"use client";

/** Audit log (Faz 05): yalnızca admin; append-only denetim izi görünümü. */

import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { useState } from "react";

import { formatDateTime } from "@/components/event-bits";
import { EmptyState, ErrorState, ForbiddenState, LoadingState } from "@/components/states";
import { PanelShell } from "@/components/panel-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { ApiError, api } from "@/lib/api";
import type { AuditListResponse } from "@/lib/types";

function actionTone(action: string): "ok" | "warn" | "danger" | "neutral" {
  if (action.endsWith("success")) return "ok";
  if (action.endsWith("failed")) return "danger";
  if (action.endsWith("rate_limited")) return "warn";
  return "neutral";
}

export default function AuditPage() {
  const [page, setPage] = useState(1);
  const audit = useQuery({
    queryKey: ["audit", page],
    queryFn: () =>
      api.get<AuditListResponse>(`/api/v1/audit?page=${page}&page_size=25`),
    placeholderData: keepPreviousData,
    retry: false,
  });

  return (
    <PanelShell>
      <h1 className="mb-4 text-lg font-semibold text-slate-100">Audit Log</h1>

      {audit.isLoading ? <LoadingState /> : null}
      {audit.isError ? (
        audit.error instanceof ApiError && audit.error.status === 403 ? (
          <ForbiddenState />
        ) : (
          <ErrorState
            message={audit.error instanceof Error ? audit.error.message : "bilinmeyen hata"}
            onRetry={() => void audit.refetch()}
          />
        )
      ) : null}

      {audit.data ? (
        audit.data.items.length === 0 ? (
          <EmptyState title="Denetim kaydı yok" />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH>Zaman (UTC)</TH>
                  <TH>Aktör</TH>
                  <TH>Eylem</TH>
                  <TH>Detay</TH>
                  <TH>IP</TH>
                </TR>
              </THead>
              <TBody>
                {audit.data.items.map((entry) => (
                  <TR key={entry.id}>
                    <TD className="whitespace-nowrap font-mono text-xs">
                      {formatDateTime(entry.created_at)}
                    </TD>
                    <TD>{entry.actor}</TD>
                    <TD>
                      <Badge tone={actionTone(entry.action)}>{entry.action}</Badge>
                    </TD>
                    <TD className="max-w-xs break-all font-mono text-[11px] text-slate-500">
                      {entry.detail ? JSON.stringify(entry.detail) : "—"}
                    </TD>
                    <TD className="font-mono text-xs">{entry.client_ip ?? "—"}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
            <nav aria-label="Sayfalama" className="mt-4 flex items-center justify-between">
              <Button
                variant="outline"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                ← Önceki
              </Button>
              <span className="text-xs text-slate-500">
                Sayfa {audit.data.page} / {Math.max(1, audit.data.pages)}
              </span>
              <Button
                variant="outline"
                disabled={page >= audit.data.pages}
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
