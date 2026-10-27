"use client";

/**
 * Müdahale önerisi detayı (Faz 07).
 *
 * Güvenlik kuralları:
 * - Onay/ret/yürütme YALNIZCA admin (yetki kararı backend'de; buradaki
 *   gizleme kozmetiktir).
 * - Görev ayrımı: öneren kendi önerisini onaylayamaz — sunucu 409 döner;
 *   arayüz uyarı metnini önceden gösterir.
 * - Yürütme dry_run modunda daima SİMÜLASYON: yanıt "SİMÜLASYON" rozetiyle
 *   gösterilir (mock AI yasağıyla aynı dürüstlük ilkesi).
 * - Politika kararı (checks) ve kanıt paketi tam olarak görüntülenir:
 *   "neden reddedildi" sorusu buradan cevaplanır.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { useState } from "react";

import { formatDateTime } from "@/components/event-bits";
import { ErrorState, LoadingState } from "@/components/states";
import { PanelShell } from "@/components/panel-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type {
  RemediationActionDetail,
  RemediationActionResponse,
} from "@/lib/types";

const STATUS_LABEL: Record<string, string> = {
  proposed: "onay bekliyor",
  approved: "onaylı",
  rejected: "reddedildi",
  expired: "süresi doldu",
  executed: "yürütüldü",
  failed: "başarısız",
};

const STATUS_TONE: Record<string, "neutral" | "ok" | "warn" | "danger" | "info"> = {
  proposed: "info",
  approved: "warn",
  rejected: "neutral",
  expired: "neutral",
  executed: "ok",
  failed: "danger",
};

const CHECK_LABEL: Record<string, string> = {
  action_in_allowlist: "allowlist üyeliği",
  params_valid: "tip parametre doğrulaması",
  action_enabled: "operatör anahtarı",
  default_blocked_gate: "kritik aksiyon kapısı",
  target_scope: "hedef kapsamı",
};

export default function RemediationDetailPage() {
  const params = useParams<{ id: string }>();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const queryClient = useQueryClient();
  const [decisionError, setDecisionError] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [lastReplayed, setLastReplayed] = useState(false);

  const detail = useQuery({
    queryKey: ["remediation-action", params.id],
    queryFn: () =>
      api.get<RemediationActionDetail>(`/api/v1/remediation/actions/${params.id}`),
  });

  const invalidate = () =>
    void queryClient.invalidateQueries({ queryKey: ["remediation-action", params.id] });

  const approve = useMutation({
    mutationFn: () =>
      api.post<RemediationActionResponse>(
        `/api/v1/remediation/actions/${params.id}/approve`,
        {},
      ),
    onSuccess: () => {
      setDecisionError(null);
      invalidate();
    },
    onError: (error) =>
      setDecisionError(error instanceof Error ? error.message : "Onaylanamadı."),
  });

  const reject = useMutation({
    mutationFn: () =>
      api.post<RemediationActionResponse>(
        `/api/v1/remediation/actions/${params.id}/reject`,
        { reason: rejectReason },
      ),
    onSuccess: () => {
      setDecisionError(null);
      setRejectReason("");
      invalidate();
    },
    onError: (error) =>
      setDecisionError(error instanceof Error ? error.message : "Reddedilemedi."),
  });

  const execute = useMutation({
    mutationFn: () =>
      api.post<RemediationActionResponse>(
        `/api/v1/remediation/actions/${params.id}/execute`,
        { execution_key: `exec-${crypto.randomUUID()}` },
      ),
    onSuccess: (response) => {
      setDecisionError(null);
      setLastReplayed(response.replayed);
      invalidate();
    },
    onError: (error) =>
      setDecisionError(error instanceof Error ? error.message : "Yürütülemedi."),
  });

  if (detail.isLoading) {
    return (
      <PanelShell>
        <LoadingState label="Öneri detayı yükleniyor…" />
      </PanelShell>
    );
  }
  if (detail.isError) {
    return (
      <PanelShell>
        <ErrorState
          message={detail.error instanceof Error ? detail.error.message : ""}
          onRetry={() => void detail.refetch()}
        />
      </PanelShell>
    );
  }

  const action = detail.data;
  if (!action) return null;
  const evidence = action.evidence ?? {};
  const checks = action.policy_decision?.checks ?? [];
  const isSelfProposal =
    user?.username === action.requested_by_username && !action.approved_by_username;

  return (
    <PanelShell>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-lg font-semibold text-slate-100">
          Müdahale önerisi: {action.action_title}
        </h1>
        <div className="flex items-center gap-2">
          <Badge tone={STATUS_TONE[action.status] ?? "neutral"}>
            {STATUS_LABEL[action.status] ?? action.status}
          </Badge>
          {action.status === "executed" &&
          action.execution_result?.simulated === true ? (
            <Badge tone="ai">SİMÜLASYON — sistem değişikliği yapılmadı</Badge>
          ) : null}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Öneri kartı */}
        <Card className="border-slate-800 bg-slate-900/40">
          <CardHeader>
            <CardTitle className="text-base text-slate-100">Öneri</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 text-xs">
            <Row label="aksiyon tipi" value={action.action_type} mono />
            <Row label="risk" value={action.risk_level} />
            <Row label="öneren" value={action.requested_by_username} />
            <Row label="onaylayan" value={action.approved_by_username ?? "—"} />
            <Row label="oluşturma" value={formatDateTime(action.created_at)} />
            <Row label="onay" value={formatDateTime(action.approved_at)} />
            <Row label="yürütme" value={formatDateTime(action.executed_at)} />
            <div className="pt-2">
              <div className="mb-1 text-[11px] text-slate-500">gerekçe</div>
              <p className="rounded border border-slate-800 bg-slate-950/60 p-2 text-slate-300">
                {action.justification}
              </p>
            </div>
            <div className="pt-2">
              <div className="mb-1 text-[11px] text-slate-500">
                tip parametreler (serbest komut yok)
              </div>
              <pre className="overflow-x-auto rounded border border-slate-800 bg-slate-950/60 p-2 font-mono text-[11px] text-slate-300">
                {JSON.stringify(action.params, null, 2)}
              </pre>
            </div>
            {action.rejected_reason ? (
              <div className="pt-2 text-red-300">
                ret gerekçesi: {action.rejected_reason} ({action.rejected_by_username})
              </div>
            ) : null}
            {action.execution_error ? (
              <div className="pt-2 text-red-300">hata: {action.execution_error}</div>
            ) : null}
          </CardContent>
        </Card>

        {/* Kanıt paketi kartı */}
        <Card className="border-slate-800 bg-slate-900/40">
          <CardHeader>
            <CardTitle className="text-base text-slate-100">Kanıt paketi</CardTitle>
            <Badge tone="neutral">sunucu üretimi</Badge>
          </CardHeader>
          <CardContent className="space-y-1 text-xs">
            <Row label="alert_id'ler" value={(evidence.alert_ids ?? []).join(", ")} mono />
            <Row label="rule_id'ler" value={(evidence.rule_ids ?? []).join(", ")} mono />
            <Row label="agent'lar" value={(evidence.agent_names ?? []).join(", ")} />
            <Row label="kaynak IP'ler" value={(evidence.src_ips ?? []).join(", ")} mono />
            <Row label="en yüksek seviye" value={String(evidence.max_rule_level ?? "—")} />
            <Row
              label="pencere"
              value={`${formatDateTime(evidence.window_start)} → ${formatDateTime(evidence.window_end)}`}
            />
            <Row label="kanıt olay sayısı" value={String((evidence.event_ids ?? []).length)} />
            <div className="pt-2">
              <div className="mb-1 text-[11px] text-slate-500">risk açıklaması</div>
              <p className="rounded border border-slate-800 bg-slate-950/60 p-2 text-slate-300">
                {evidence.risk_explanation ?? "—"}
              </p>
            </div>
            <div className="pt-2">
              <div className="mb-1 text-[11px] text-slate-500">geri alma / mitigation</div>
              <p className="rounded border border-slate-800 bg-slate-950/60 p-2 text-slate-300">
                {evidence.rollback_note ?? "—"}
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Politika karar izi */}
        <Card className="border-slate-800 bg-slate-900/40">
          <CardHeader>
            <CardTitle className="text-base text-slate-100">Politika kararı</CardTitle>
            <Badge tone={action.policy_decision?.allowed ? "ok" : "danger"}>
              {action.policy_decision?.allowed ? "kabul" : "reddedildi"}
            </Badge>
          </CardHeader>
          <CardContent className="space-y-1 text-xs">
            {checks.length === 0 ? (
              <p className="text-slate-500">Karar izi boş.</p>
            ) : (
              checks.map((check) => (
                <div key={check.name} className="flex items-start gap-2 py-0.5">
                  <span aria-hidden>{check.passed ? "✓" : "✗"}</span>
                  <span className="text-slate-300">
                    {CHECK_LABEL[check.name] ?? check.name}
                  </span>
                  <span className="ml-auto text-right text-[11px] text-slate-500">
                    {check.detail}
                  </span>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        {/* Yürütme sonucu */}
        <Card className="border-slate-800 bg-slate-900/40">
          <CardHeader>
            <CardTitle className="text-base text-slate-100">Yürütme sonucu</CardTitle>
            {action.execution_count > 0 ? (
              <Badge tone="neutral">{action.execution_count} yürütme</Badge>
            ) : null}
          </CardHeader>
          <CardContent className="space-y-2 text-xs">
            {action.execution_result ? (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={action.execution_result.success ? "ok" : "danger"}>
                    {action.execution_result.success ? "başarılı" : "başarısız"}
                  </Badge>
                  <Badge tone="ai">simulated: {String(action.execution_result.simulated)}</Badge>
                  <span className="text-slate-500">
                    {action.execution_result.duration_ms} ms
                  </span>
                </div>
                <pre className="overflow-x-auto rounded border border-slate-800 bg-slate-950/60 p-2 font-mono text-[11px] text-slate-300">
                  {JSON.stringify(action.execution_result.output, null, 2)}
                </pre>
              </>
            ) : (
              <p className="text-slate-500">Henüz yürütülmedi.</p>
            )}
            {isAdmin && (action.status === "approved" || action.status === "executed" || action.status === "failed") ? (
              <div className="pt-2">
                <Button
                  disabled={execute.isPending}
                  onClick={() => execute.mutate()}
                >
                  {execute.isPending
                    ? "Yürütülüyor…"
                    : action.status === "approved"
                      ? "Yürüt (dry-run simülasyon)"
                      : "Yürütmeyi tekrarla (replay)"}
                </Button>
                {lastReplayed ? (
                  <span className="ml-2 text-[11px] text-slate-400">
                    Tekrar oynatılan istek: orijinal sonuç döndü (çift yürütme yok).
                  </span>
                ) : null}
              </div>
            ) : null}
          </CardContent>
        </Card>

        {/* Onay/ret (admin; proposed) */}
        {isAdmin && action.status === "proposed" ? (
          <Card className="border-amber-900/50 bg-amber-950/10 lg:col-span-2">
            <CardHeader>
              <CardTitle className="text-base text-slate-100">Karar (admin)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {isSelfProposal ? (
                <p className="text-xs text-amber-300">
                  Görev ayrımı: bu öneriyi SİZ oluşturdunuz; kendi önerinizi
                  onaylayamazsınız (başka bir admin hesabı gerekir).
                </p>
              ) : null}
              <label className="block text-xs text-slate-400">
                Ret gerekçesi (yalnızca ret için; en az 5 karakter)
                <input
                  value={rejectReason}
                  onChange={(event) => setRejectReason(event.target.value)}
                  className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200"
                />
              </label>
              {decisionError ? (
                <div role="alert" className="rounded-lg border border-red-900/60 bg-red-950/30 p-3 text-xs text-red-300">
                  {decisionError}
                </div>
              ) : null}
              <div className="flex gap-2">
                <Button disabled={approve.isPending} onClick={() => approve.mutate()}>
                  {approve.isPending ? "Onaylanıyor…" : "Onayla"}
                </Button>
                <Button
                  variant="outline"
                  disabled={reject.isPending || rejectReason.trim().length < 5}
                  onClick={() => reject.mutate()}
                >
                  {reject.isPending ? "Reddediliyor…" : "Ret"}
                </Button>
              </div>
            </CardContent>
          </Card>
        ) : null}
      </div>
    </PanelShell>
  );
}

function Row({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-2 py-0.5">
      <span className="w-32 shrink-0 text-[11px] text-slate-500">{label}</span>
      <span className={mono ? "break-all font-mono text-[11px] text-slate-300" : "text-[11px] text-slate-300"}>
        {value || "—"}
      </span>
    </div>
  );
}
