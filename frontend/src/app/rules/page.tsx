"use client";

/**
 * Korelasyon kural kataloğu (Faz 06).
 *
 * - Tüm roller kataloğu GÖRÜNTÜLEYEBİLİR (sürümler + parametreler).
 * - Yalnızca admin etkinlik anahtarını değiştirebilir (PATCH; değişiklik
 *   backend audit log'una yazılır — yetki kararı sunucudadır).
 * - Kapatılan kural döngüde değerlendirilmez; mevcut tespitler silinmez.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorState, LoadingState } from "@/components/states";
import { PanelShell } from "@/components/panel-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { CorrelationRuleListResponse, CorrelationRuleUpdateResponse } from "@/lib/types";

const KIND_LABEL: Record<string, string> = {
  burst: "yoğunluk (eşik)",
  sequence: "sıralı (önce→sonra)",
};

export default function RulesPage() {
  const { isAdmin } = useAuth();
  const queryClient = useQueryClient();
  const [actionError, setActionError] = useState<string | null>(null);

  const rules = useQuery({
    queryKey: ["correlation-rules"],
    queryFn: () => api.get<CorrelationRuleListResponse>("/api/v1/correlation-rules"),
  });

  const toggle = useMutation({
    mutationFn: ({ key, enabled }: { key: string; enabled: boolean }) =>
      api.patch<CorrelationRuleUpdateResponse>(
        `/api/v1/correlation-rules/${key}`,
        { enabled },
      ),
    onSuccess: () => {
      setActionError(null);
      void queryClient.invalidateQueries({ queryKey: ["correlation-rules"] });
    },
    onError: (error) => {
      setActionError(error instanceof Error ? error.message : "İşlem başarısız.");
    },
  });

  return (
    <PanelShell>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-lg font-semibold text-slate-100">Korelasyon Kuralları</h1>
        <span className="text-xs text-slate-500">
          {rules.data ? `${rules.data.items.length} kural · v${rules.data.items.map((r) => r.version).join(", v")}` : null}
        </span>
      </div>

      <p className="mb-4 rounded-lg border border-slate-800 bg-slate-900/40 p-3 text-xs text-slate-400">
        Kurallar basit ve açıklanabilir karar mantığıdır (ML/anomali algoritması
        yoktur). Kural tanımı koddaki sürümlenmiş kataloktan gelir; sürüm
        değişimleri audit log'una işlenir. Yalnızca yönetici kuralları
        açıp kapatabilir; değişiklikler denetim izine yazılır.
      </p>

      {rules.isLoading ? <LoadingState /> : null}
      {rules.isError ? (
        <ErrorState
          message={rules.error instanceof Error ? rules.error.message : ""}
          onRetry={() => void rules.refetch()}
        />
      ) : null}
      {actionError ? (
        <div role="alert" className="mb-4 rounded-lg border border-red-900/60 bg-red-950/30 p-3 text-xs text-red-300">
          {actionError}
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {(rules.data?.items ?? []).map((rule) => (
          <Card key={rule.key} className="border-slate-800 bg-slate-900/40">
            <CardHeader>
              <CardTitle className="flex flex-wrap items-center justify-between gap-2 text-base">
                <span className="text-slate-100">{rule.name}</span>
                <Badge
                  className={
                    rule.enabled
                      ? "border-emerald-800 bg-emerald-950/40 text-emerald-300"
                      : "border-slate-700 bg-slate-900 text-slate-500"
                  }
                >
                  {rule.enabled ? "etkin" : "kapalı"}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-xs">
              <p className="text-slate-400">{rule.description}</p>
              <div className="rounded border border-slate-800 bg-slate-950/60 p-2 font-mono text-[11px] text-slate-400">
                <div>
                  tür: {KIND_LABEL[rule.kind] ?? rule.kind} · sürüm: v{rule.version}
                </div>
                <div>
                  pencere: {rule.params.window_seconds}s
                  {rule.params.threshold ? ` · eşik: ${rule.params.threshold} olay` : ""}
                </div>
                <div>grup: {(rule.params.group_by ?? []).join(" + ")}</div>
                {(rule.params.match_rule_groups ?? []).length > 0 ? (
                  <div>filtre (ilk): {(rule.params.match_rule_groups ?? []).join(", ")}</div>
                ) : null}
                {(rule.params.then_rule_groups ?? []).length > 0 ||
                (rule.params.then_rule_ids ?? []).length > 0 ? (
                  <div>
                    filtre (sonra):{" "}
                    {[...(rule.params.then_rule_groups ?? []), ...(rule.params.then_rule_ids ?? [])].join(", ")}
                  </div>
                ) : null}
              </div>
              {isAdmin ? (
                <div className="flex items-center gap-2">
                  <Button
                    disabled={toggle.isPending}
                    onClick={() =>
                      toggle.mutate({ key: rule.key, enabled: !rule.enabled })
                    }
                  >
                    {rule.enabled ? "Kuralı kapat" : "Kuralı aç"}
                  </Button>
                  <span className="text-[11px] text-slate-500">
                    Değişiklik audit log'a yazılır.
                  </span>
                </div>
              ) : (
                <span className="text-[11px] text-slate-500">
                  Etkinlik anahtarını yalnızca yönetici değiştirebilir.
                </span>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </PanelShell>
  );
}
