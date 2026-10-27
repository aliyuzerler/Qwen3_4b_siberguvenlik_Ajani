"use client";

/**
 * Ayarlar (Faz 05): yalnızca admin. Salt okunur görünüm — secret değeri
 * HİÇBİR koşulda gösterilmez (backend şeması da döndürmez). Bildirim
 * ayarları Faz 08 yol haritası olarak işaretlidir.
 */

import { useQuery } from "@tanstack/react-query";

import { ErrorState, ForbiddenState, LoadingState } from "@/components/states";
import { PanelShell } from "@/components/panel-shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError, api } from "@/lib/api";
import type { SettingsResponse } from "@/lib/types";

function Row({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-3 py-1.5 text-sm">
      <span className="w-52 shrink-0 text-xs font-medium text-slate-500">{label}</span>
      <span className={mono ? "break-all font-mono text-xs text-slate-300" : "text-slate-300"}>
        {value}
      </span>
    </div>
  );
}

export default function SettingsPage() {
  const settings = useQuery({
    queryKey: ["settings"],
    queryFn: () => api.get<SettingsResponse>("/api/v1/settings"),
    retry: false,
  });

  return (
    <PanelShell>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-lg font-semibold text-slate-100">Ayarlar</h1>
        <span className="text-xs text-slate-500">
          Değişiklik için backend .env + yeniden başlatma (bu fazda panel
          üzerinden güncelleme yoktur)
        </span>
      </div>

      {settings.isLoading ? <LoadingState /> : null}
      {settings.isError ? (
        settings.error instanceof ApiError && settings.error.status === 403 ? (
          <ForbiddenState />
        ) : (
          <ErrorState
            message={settings.error instanceof Error ? settings.error.message : "bilinmeyen hata"}
            onRetry={() => void settings.refetch()}
          />
        )
      ) : null}

      {settings.data ? (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Model</CardTitle>
              <Badge tone="info">{settings.data.policy_mode}</Badge>
            </CardHeader>
            <CardContent className="divide-y divide-slate-800/40">
              <Row label="Model tag" value={settings.data.model.model_tag} mono />
              <Row label="Kuantizasyon" value={settings.data.model.model_quantization} mono />
              <Row label="Ollama uç noktası" value={settings.data.ollama_base_url} mono />
              <Row
                label="Analiz döngüsü"
                value={settings.data.model.analysis_enabled ? "etkin" : "kapalı (kill switch)"}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Saklama ve maskeleme</CardTitle>
            </CardHeader>
            <CardContent className="divide-y divide-slate-800/40">
              <Row label="Saklama süresi" value={`${settings.data.retention_days} gün`} />
              <Row label="Maskeleme" value={settings.data.redaction.enabled ? "etkin" : "kapalı"} />
              <Row label="IP modu" value={settings.data.redaction.ip_mode} />
              <Row label="E-posta modu" value={settings.data.redaction.email_mode} />
              <Row
                label="Secret desenleri"
                value={settings.data.redaction.secret_patterns ? "tarıyor" : "kapalı"}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Worker</CardTitle>
            </CardHeader>
            <CardContent className="divide-y divide-slate-800/40">
              <Row
                label="Birleşik döngü"
                value={settings.data.worker.loop_enabled ? "açık" : "kapalı (varsayılan)"}
              />
              <Row label="Aralık" value={`${settings.data.worker.interval_seconds} sn`} />
              <Row label="Eşzamanlılık" value={String(settings.data.worker.concurrency)} />
              <Row label="Toplu boyut" value={String(settings.data.worker.batch_size)} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Müdahale hazırlığı (Faz 07)</CardTitle>
              <Badge tone={settings.data.remediation.enabled ? "info" : "neutral"}>
                {settings.data.remediation.enabled ? settings.data.remediation.policy_mode : "kill switch"}
              </Badge>
            </CardHeader>
            <CardContent className="divide-y divide-slate-800/40">
              <Row
                label="Alt sistem"
                value={settings.data.remediation.enabled ? "açık" : "kapalı (kill switch)"}
              />
              <Row label="Politika modu" value={settings.data.remediation.policy_mode} />
              <Row
                label="Onay penceresi"
                value={`${settings.data.remediation.approval_ttl_minutes} dk`}
              />
              <Row
                label="Hız tavanı"
                value={`${settings.data.remediation.rate_limit_per_hour}/saat (kullanıcı)`}
              />
              <Row
                label="Kritik aksiyon kapısı"
                value={
                  settings.data.remediation.allow_blocked_actions
                    ? "AÇIK (global) — prod'da yasak"
                    : "kapalı (firewall/SSH/hesap engelli)"
                }
              />
              <Row
                label="Kendi önerisini onaylama"
                value={settings.data.remediation.allow_self_approval ? "izinli (istisna)" : "yasak (görev ayrımı)"}
              />
              <Row
                label="Yürütücü zaman aşımı"
                value={`${settings.data.remediation.executor_timeout_seconds} sn`}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Bildirimler</CardTitle>
              <Badge tone="neutral">Faz 08 — yol haritası</Badge>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-slate-400">{settings.data.notifications.roadmap_note}</p>
            </CardContent>
          </Card>

          <Card className="lg:col-span-2 border-amber-900/50 bg-amber-950/10">
            <CardContent className="text-xs text-amber-300/90">
              Güvenlik notu: Hassas değerler (JWT secret, Wazuh parolası, bootstrap
              parolası) bu ekranda ASLA gösterilmez; yalnızca backend .env üzerinden
              yönetilir. Model değerlendirmesi panelde orijinal Wazuh verisinden
              ayrı kartta sunulur ve doğrulanma amacı taşır.
            </CardContent>
          </Card>
        </div>
      ) : null}
    </PanelShell>
  );
}
