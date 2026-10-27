"use client";

/**
 * Müdahale hazırlık listesi (Faz 07).
 *
 * Güvenlik çerçevesi (phases/07):
 * - Bu ekran SİSTEM DEĞİŞİKLİĞİ YAPMAZ: yürütme observe_only modunda
 *   engellenir, dry_run modunda yalnızca SİMÜLASYONdur (simulated rozeti).
 * - Öneri analyst+, onay/ret/yürütme YALNIZCA admin; öneren kendi
 *   önerisini onaylayamaz (görev ayrımı — kararı sunucu verir).
 * - Katalog (allowlist): tipli aksiyonlar; serbest shell komutu yoktur.
 *   Firewall/SSH/hesap aksiyonları VARSAYILAN ENGELLİ'dir.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";

import { formatDateTime } from "@/components/event-bits";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import { PanelShell } from "@/components/panel-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type {
  RemediationActionListResponse,
  RemediationCatalogItem,
  RemediationCatalogResponse,
} from "@/lib/types";

const STATUS_TONE: Record<string, "neutral" | "ok" | "warn" | "danger" | "info"> = {
  proposed: "info",
  approved: "warn",
  rejected: "neutral",
  expired: "neutral",
  executed: "ok",
  failed: "danger",
};

const STATUS_LABEL: Record<string, string> = {
  proposed: "onay bekliyor",
  approved: "onaylı",
  rejected: "reddedildi",
  expired: "süresi doldu",
  executed: "yürütüldü",
  failed: "başarısız",
};

const RISK_TONE: Record<string, "ok" | "warn" | "danger"> = {
  low: "ok",
  medium: "warn",
  high: "danger",
};

const STATUS_FILTERS = ["", "proposed", "approved", "executed", "failed", "rejected", "expired"];

/** Aksiyon tipine göre öneri formunun tek parametre alanı etiketi. */
function paramFieldLabel(actionType: string): { name: string; label: string } | null {
  switch (actionType) {
    case "restart_wazuh_agent":
    case "run_antivirus_scan":
    case "isolate_host":
      return { name: "agent_id", label: "agent_id (kanıt olaylardaki)" };
    case "block_src_ip":
      return { name: "ip", label: "IP (kanıt olayların src_ip'si)" };
    case "lock_user_account":
      return { name: "username", label: "kullanıcı adı" };
    case "notify_admin":
      return { name: "note", label: "not (opsiyonel)" };
    default:
      return null;
  }
}

export default function RemediationPage() {
  const router = useRouter();
  const { user } = useAuth();
  const canPropose = user?.role === "admin" || user?.role === "analyst";
  const isAdmin = user?.role === "admin";
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("");
  const [page, setPage] = useState(1);
  const [formError, setFormError] = useState<string | null>(null);

  const actions = useQuery({
    queryKey: ["remediation-actions", statusFilter, page],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(page), page_size: "20" });
      if (statusFilter) params.set("status", statusFilter);
      return api.get<RemediationActionListResponse>(
        `/api/v1/remediation/actions?${params.toString()}`,
      );
    },
  });

  const catalog = useQuery({
    queryKey: ["remediation-catalog"],
    queryFn: () => api.get<RemediationCatalogResponse>("/api/v1/remediation/catalog"),
  });

  const [actionType, setActionType] = useState("notify_admin");
  const [eventIdsText, setEventIdsText] = useState("");
  const [paramValue, setParamValue] = useState("");
  const [justification, setJustification] = useState("");

  const selectedDefinition: RemediationCatalogItem | undefined = useMemo(
    () => catalog.data?.items.find((item) => item.action_type === actionType),
    [catalog.data, actionType],
  );
  const field = paramFieldLabel(actionType);

  const propose = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<unknown>("/api/v1/remediation/actions", body),
    onSuccess: () => {
      setFormError(null);
      setEventIdsText("");
      setParamValue("");
      setJustification("");
      void queryClient.invalidateQueries({ queryKey: ["remediation-actions"] });
    },
    onError: (error) => {
      setFormError(error instanceof Error ? error.message : "Öneri oluşturulamadı.");
    },
  });

  function submitProposal() {
    const eventIds = eventIdsText
      .split(/[,\s]+/)
      .map((value) => value.trim())
      .filter(Boolean);
    if (eventIds.length === 0) {
      setFormError("En az bir kanıt olay kimliği (UUID) gerekir.");
      return;
    }
    if (justification.trim().length < 10) {
      setFormError("Gerekçe en az 10 karakter olmalıdır.");
      return;
    }
    const params: Record<string, string> = {};
    if (field && paramValue.trim()) params[field.name] = paramValue.trim();
    propose.mutate({
      action_type: actionType,
      params,
      event_ids: eventIds,
      justification: justification.trim(),
      idempotency_key: `panel-${crypto.randomUUID()}`,
    });
  }

  return (
    <PanelShell>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-lg font-semibold text-slate-100">Müdahale Hazırlığı</h1>
        <div className="flex items-center gap-2">
          <Badge tone={catalog.data?.remediation_enabled ? "info" : "danger"}>
            kill switch: {catalog.data?.remediation_enabled ? "kapalı" : "açık"}
          </Badge>
          <Badge tone="neutral">mod: {catalog.data?.policy_mode ?? "…"}</Badge>
        </div>
      </div>

      <p className="mb-4 rounded-lg border border-slate-800 bg-slate-900/40 p-3 text-xs text-slate-400">
        Model eylem BAŞLATAMAZ: öneri yalnızca kimlikli kullanıcı tarafından
        yapılır ve deterministik politika motorundan geçer. Yürütme
        observe_only modunda engellenir; dry_run modunda yalnızca
        SİMÜLASYONdur (sistemde değişiklik yapan kod yolu yoktur).
        Firewall/SSH/hesap aksiyonları varsayılan ENGELLİ'dir.
      </p>

      {/* --- Yeni öneri (analyst+) --- */}
      {canPropose ? (
        <Card className="mb-6 border-slate-800 bg-slate-900/40">
          <CardHeader>
            <CardTitle className="text-base text-slate-100">Yeni öneri</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <label className="block text-xs text-slate-400">
                Aksiyon tipi (allowlist)
                <select
                  value={actionType}
                  onChange={(event) => {
                    setActionType(event.target.value);
                    setParamValue("");
                  }}
                  className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200"
                >
                  {(catalog.data?.items ?? []).map((item) => (
                    <option key={item.action_type} value={item.action_type}>
                      {item.title}
                      {item.default_blocked ? " (varsayılan engelli)" : ""}
                    </option>
                  ))}
                </select>
              </label>
              {field ? (
                <label className="block text-xs text-slate-400">
                  {field.label}
                  <Input
                    value={paramValue}
                    onChange={(event) => setParamValue(event.target.value)}
                    className="mt-1"
                    placeholder={field.name}
                  />
                </label>
              ) : null}
            </div>
            <label className="block text-xs text-slate-400">
              Kanıt olay kimlikleri (event UUID, virgülle ayırın)
              <Input
                value={eventIdsText}
                onChange={(event) => setEventIdsText(event.target.value)}
                className="mt-1 font-mono text-xs"
                placeholder="11111111-1111-1111-1111-111111111111, …"
              />
            </label>
            <label className="block text-xs text-slate-400">
              Gerekçe (zorunlu; audit'e yazılır)
              <textarea
                value={justification}
                onChange={(event) => setJustification(event.target.value)}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200"
                rows={2}
                placeholder="Bu önerinin gerekçesi…"
              />
            </label>
            {selectedDefinition ? (
              <div className="rounded border border-slate-800 bg-slate-950/60 p-2 text-[11px] text-slate-400">
                <div className="flex flex-wrap items-center gap-1">
                  <span>risk:</span>
                  <Badge tone={RISK_TONE[selectedDefinition.risk_level]}>
                    {selectedDefinition.risk_level}
                  </Badge>
                  {selectedDefinition.default_blocked ? (
                    <Badge tone="danger">varsayılan engelli (iki kapı gerekir)</Badge>
                  ) : null}
                </div>
                <div className="mt-1">{selectedDefinition.risk_explanation}</div>
              </div>
            ) : null}
            {formError ? (
              <div role="alert" className="rounded-lg border border-red-900/60 bg-red-950/30 p-3 text-xs text-red-300">
                {formError}
              </div>
            ) : null}
            <Button disabled={propose.isPending} onClick={submitProposal}>
              {propose.isPending ? "Gönderiliyor…" : "Öneriyi oluştur"}
            </Button>
          </CardContent>
        </Card>
      ) : null}

      {/* --- Öneri listesi --- */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {STATUS_FILTERS.map((value) => (
          <button
            key={value || "all"}
            type="button"
            onClick={() => {
              setStatusFilter(value);
              setPage(1);
            }}
            aria-current={statusFilter === value ? "true" : undefined}
            className={
              statusFilter === value
                ? "rounded-md bg-slate-800 px-3 py-1 text-xs font-medium text-slate-100"
                : "rounded-md px-3 py-1 text-xs text-slate-400 hover:bg-slate-900"
            }
          >
            {value ? STATUS_LABEL[value] ?? value : "tümü"}
          </button>
        ))}
      </div>

      {actions.isLoading ? <LoadingState /> : null}
      {actions.isError ? (
        <ErrorState
          message={actions.error instanceof Error ? actions.error.message : ""}
          onRetry={() => void actions.refetch()}
        />
      ) : null}
      {actions.data && actions.data.items.length === 0 ? (
        <EmptyState
          title="Öneri yok"
          hint="Henüz müdahale önerisi oluşturulmamış."
        />
      ) : null}

      {actions.data && actions.data.items.length > 0 ? (
        <Card className="border-slate-800 bg-slate-900/40">
          <CardContent className="p-0">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-800 text-xs text-slate-500">
                <tr>
                  <th className="px-4 py-2 font-medium">Aksiyon</th>
                  <th className="px-4 py-2 font-medium">Risk</th>
                  <th className="px-4 py-2 font-medium">Durum</th>
                  <th className="px-4 py-2 font-medium">Öneren</th>
                  <th className="px-4 py-2 font-medium">Onaylayan</th>
                  <th className="px-4 py-2 font-medium">Tarih</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {actions.data.items.map((action) => (
                  <tr
                    key={action.id}
                    className="cursor-pointer hover:bg-slate-900/60"
                    onClick={() => void router.push(`/remediation/${action.id}`)}
                  >
                    <td className="px-4 py-2 text-slate-200">{action.action_title}</td>
                    <td className="px-4 py-2">
                      <Badge tone={RISK_TONE[action.risk_level]}>{action.risk_level}</Badge>
                    </td>
                    <td className="px-4 py-2">
                      <Badge tone={STATUS_TONE[action.status] ?? "neutral"}>
                        {STATUS_LABEL[action.status] ?? action.status}
                      </Badge>
                    </td>
                    <td className="px-4 py-2 text-xs text-slate-400">
                      {action.requested_by_username}
                    </td>
                    <td className="px-4 py-2 text-xs text-slate-400">
                      {action.approved_by_username ?? "—"}
                    </td>
                    <td className="px-4 py-2 text-xs text-slate-500">
                      {formatDateTime(action.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      ) : null}

      {actions.data && actions.data.pages > 1 ? (
        <div className="mt-3 flex items-center justify-end gap-2 text-xs text-slate-400">
          <Button
            variant="outline"
            disabled={page <= 1}
            onClick={() => setPage((current) => current - 1)}
          >
            Önceki
          </Button>
          <span>
            sayfa {actions.data.page} / {actions.data.pages} · toplam {actions.data.total}
          </span>
          <Button
            variant="outline"
            disabled={page >= actions.data.pages}
            onClick={() => setPage((current) => current + 1)}
          >
            Sonraki
          </Button>
        </div>
      ) : null}

      {/* --- Katalog (allowlist) --- */}
      <h2 className="mb-3 mt-8 text-base font-semibold text-slate-100">
        Aksiyon kataloğu (allowlist)
      </h2>
      {catalog.isLoading ? <LoadingState /> : null}
      {catalog.isError ? (
        <ErrorState
          message={catalog.error instanceof Error ? catalog.error.message : ""}
          onRetry={() => void catalog.refetch()}
        />
      ) : null}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {(catalog.data?.items ?? []).map((item) => (
          <Card key={item.action_type} className="border-slate-800 bg-slate-900/40">
            <CardHeader>
              <CardTitle className="flex flex-wrap items-center gap-2 text-sm text-slate-100">
                {item.title}
                <Badge tone={RISK_TONE[item.risk_level]}>{item.risk_level}</Badge>
                <Badge tone={item.enabled ? "ok" : "neutral"}>
                  {item.enabled ? "etkin" : "kapalı"}
                </Badge>
                {item.default_blocked ? (
                  <Badge tone="danger">varsayılan engelli</Badge>
                ) : null}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-xs text-slate-400">
              <p>{item.description}</p>
              <p>
                <span className="text-slate-500">hedef kapsamı:</span>{" "}
                <span className="font-mono">{item.target_scope}</span>
              </p>
              <p>
                <span className="text-slate-500">geri alma:</span> {item.rollback_note}
              </p>
              {isAdmin ? (
                <p className="text-[11px] text-slate-500">
                  Katalog etkinlik anahtarı PATCH ucuyla (admin) değiştirilir;
                  değişim audit'e yazılır; engelliler için global kapı gerekir.
                </p>
              ) : null}
            </CardContent>
          </Card>
        ))}
      </div>
    </PanelShell>
  );
}
