"use client";

/**
 * Korelasyon listesi (Faz 06).
 *
 * Görünürlük ilkesi: her satır KURAL çıktısıdır (kural adı + sürüm + pencere
 * + tekrar sayacı + kanıt). Model (LLM) yorumu BURADA GÖSTERİLMEZ; olay
 * başına ayrı analiz kartları detay sayfasında ve Olaylar bölümündedir
 * (AGENTS.md §5 — kural çıktısı ile LLM yorumu ayrı tutulmalı).
 */

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import { formatDateTime, levelTone } from "@/components/event-bits";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import { PanelShell } from "@/components/panel-shell";
import { Button } from "@/components/ui/button";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { CorrelationListResponse, CorrelationRuleListResponse } from "@/lib/types";

const TONE_CLASS: Record<string, string> = {
  ok: "border-emerald-800 bg-emerald-950/40 text-emerald-300",
  warn: "border-amber-800 bg-amber-950/40 text-amber-300",
  danger: "border-red-800 bg-red-950/40 text-red-300",
  neutral: "border-slate-700 bg-slate-900 text-slate-400",
};

export default function CorrelationsPage() {
  const [page, setPage] = useState(1);
  const [ruleKey, setRuleKey] = useState("");
  const [agentName, setAgentName] = useState("");

  const rules = useQuery({
    queryKey: ["correlation-rules"],
    queryFn: () => api.get<CorrelationRuleListResponse>("/api/v1/correlation-rules"),
  });

  const correlations = useQuery({
    queryKey: ["correlations", { page, ruleKey, agentName }],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(page), page_size: "25" });
      if (ruleKey) params.set("rule_key", ruleKey);
      if (agentName) params.set("agent_name", agentName);
      return api.get<CorrelationListResponse>(
        `/api/v1/correlations?${params.toString()}`,
      );
    },
    placeholderData: keepPreviousData,
  });

  return (
    <PanelShell>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-lg font-semibold text-slate-100">Korelasyonlar</h1>
        {correlations.data ? (
          <span className="text-xs text-slate-500">
            {correlations.data.total} tespit
          </span>
        ) : null}
      </div>

      <p className="mb-4 rounded-lg border border-slate-800 bg-slate-900/40 p-3 text-xs text-slate-400">
        Bu liste kural motorunun (deterministik) çıktısıdır; AI değerlendirmesi
        içermez. Her tespit eşleşen olaylarla kanıt bağlantısıyla izlenebilir.
      </p>

      {/* Filtreler */}
      <form
        aria-label="Korelasyon filtreleri"
        className="mb-4 grid grid-cols-1 gap-3 rounded-lg border border-slate-800 bg-slate-900/40 p-4 sm:grid-cols-3"
        onSubmit={(e) => {
          e.preventDefault();
          setPage(1);
          void correlations.refetch();
        }}
      >
        <div>
          <Label htmlFor="c-rule">Kural</Label>
          <Select
            id="c-rule"
            value={ruleKey}
            onChange={(e) => {
              setRuleKey(e.target.value);
              setPage(1);
            }}
          >
            <option value="">Tümü</option>
            {(rules.data?.items ?? []).map((rule) => (
              <option key={rule.key} value={rule.key}>
                {rule.name}
                {rule.enabled ? "" : " (kapalı)"}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="c-agent">Agent adı</Label>
          <Input
            id="c-agent"
            value={agentName}
            onChange={(e) => {
              setAgentName(e.target.value);
              setPage(1);
            }}
            placeholder="örn. web-server-01"
          />
        </div>
        <div className="flex items-end">
          <Button type="submit" variant="outline">
            Filtrele
          </Button>
        </div>
      </form>

      {correlations.isLoading ? <LoadingState /> : null}
      {correlations.isError ? (
        <ErrorState
          message={correlations.error instanceof Error ? correlations.error.message : ""}
          onRetry={() => void correlations.refetch()}
        />
      ) : null}
      {correlations.data && correlations.data.items.length === 0 ? (
        <EmptyState
          title="Korelasyon tespiti yok"
          hint="Henüz hiçbir kural eşleşmesi üretilmedi ya da filtre sonucu boş."
        />
      ) : null}

      {correlations.data && correlations.data.items.length > 0 ? (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <Table>
            <THead>
              <TR>
                <TH>Kural</TH>
                <TH>Pencere (UTC)</TH>
                <TH>Olay</TH>
                <TH>En yüksek seviye</TH>
                <TH>Tekrar</TH>
                <TH>Kanıt</TH>
                <TH aria-label="detay" />
              </TR>
            </THead>
            <TBody>
              {correlations.data.items.map((item) => (
                <TR key={item.id}>
                  <TD>
                    <div className="font-medium text-slate-200">{item.rule_name}</div>
                    <div className="text-[11px] text-slate-500">
                      {item.rule_key} · v{item.rule_version}
                    </div>
                  </TD>
                  <TD className="whitespace-nowrap text-xs text-slate-400">
                    {formatDateTime(item.window_start)}
                    <br />
                    → {formatDateTime(item.window_end)}
                  </TD>
                  <TD className="text-sm text-slate-300">{item.event_count}</TD>
                  <TD>
                    <span
                      className={`rounded border px-1.5 py-0.5 text-xs ${
                        TONE_CLASS[levelTone(item.max_rule_level)]
                      }`}
                    >
                      {item.max_rule_level}
                    </span>
                  </TD>
                  <TD className="text-sm text-slate-300">
                    {item.hit_count} kez
                    <div className="text-[11px] text-slate-500">
                      son: {formatDateTime(item.last_hit_at)}
                    </div>
                  </TD>
                  <TD className="max-w-56 truncate text-xs text-slate-400">
                    {(item.evidence.agent_names ?? []).join(", ") || "—"}
                    {(item.evidence.src_ips ?? []).length > 0
                      ? ` · ${(item.evidence.src_ips ?? []).join(", ")}`
                      : ""}
                  </TD>
                  <TD>
                    <Link href={`/correlations/${item.id}`}>
                      <Button variant="outline">
                        Detay
                      </Button>
                    </Link>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </div>
      ) : null}

      {/* Sayfalama */}
      {correlations.data && correlations.data.pages > 1 ? (
        <div className="mt-4 flex items-center justify-between">
          <Button
            variant="outline"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            ← Önceki
          </Button>
          <span className="text-xs text-slate-500">
            Sayfa {correlations.data.page} / {correlations.data.pages}
          </span>
          <Button
            variant="outline"
            disabled={page >= correlations.data.pages}
            onClick={() => setPage((p) => p + 1)}
          >
            Sonraki →
          </Button>
        </div>
      ) : null}
    </PanelShell>
  );
}
