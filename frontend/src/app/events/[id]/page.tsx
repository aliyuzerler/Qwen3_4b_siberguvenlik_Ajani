"use client";

/**
 * Olay detayı (Faz 05):
 * - Orijinal kanıt kartı (Wazuh verisi — gri aile)
 * - AI değerlendirmesi kartı (mor çerçeve + "doğrulanmalı" uyarısı —
 *   model çıktısı Wazuh verisinden GÖRSEL OLARAK AYRIDIR; phases/05)
 * - Müdahale bölümü: devre dışı buton + "Faz 07" yol haritası rozeti
 * (XSS notu: tüm model/log metinleri React metin düğümü olarak basılır;
 * dangerouslySetInnerHTML bu projede hiçbir yerde kullanılmaz.)
 */

import { useQuery } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";

import { assessmentBadge, formatDateTime, levelTone } from "@/components/event-bits";
import { ErrorState, ForbiddenState, LoadingState } from "@/components/states";
import { PanelShell } from "@/components/panel-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError, api } from "@/lib/api";
import type { EventDetail } from "@/lib/types";

function EvidenceRow({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="flex gap-2 py-1 text-sm">
      <span className="w-40 shrink-0 text-xs font-medium text-slate-500">{label}</span>
      <span className="min-w-0 break-all text-slate-300">{value || "—"}</span>
    </div>
  );
}

export default function EventDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const detail = useQuery({
    queryKey: ["event", params.id],
    queryFn: () => api.get<EventDetail>(`/api/v1/events/${params.id}`),
  });

  if (detail.isLoading) {
    return (
      <PanelShell>
        <LoadingState label="Olay detayı yükleniyor…" />
      </PanelShell>
    );
  }
  if (detail.isError) {
    const error = detail.error;
    if (error instanceof ApiError && error.status === 404) {
      return (
        <PanelShell>
          <div
            role="note"
            className="rounded-lg border border-slate-700 bg-slate-900/40 px-4 py-10 text-center text-sm text-slate-300"
          >
            Olay bulunamadı.
          </div>
        </PanelShell>
      );
    }
    if (error instanceof ApiError && error.status === 403) {
      return (
        <PanelShell>
          <ForbiddenState />
        </PanelShell>
      );
    }
    return (
      <PanelShell>
        <ErrorState
          message={error instanceof Error ? error.message : "bilinmeyen hata"}
          onRetry={() => void detail.refetch()}
        />
      </PanelShell>
    );
  }

  const event = detail.data;
  if (!event) return null;
  const analysis = event.analysis;
  const badge = analysis ? assessmentBadge(analysis.ai_assessment) : null;

  return (
    <PanelShell>
      <div className="mb-4">
        <h1 className="text-lg font-semibold text-slate-100">{event.rule_description}</h1>
        <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
          <span>alert {event.alert_id}</span>
          <span>·</span>
          <span>kaynak {event.source}</span>
          <span>·</span>
          <span>{formatDateTime(event.timestamp)} UTC</span>
          <Badge tone={levelTone(event.rule_level)}>Wazuh seviye {event.rule_level}</Badge>
          {event.seen_count > 1 ? (
            <Badge tone="neutral">{event.seen_count}× görüldü</Badge>
          ) : null}
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* --- Orijinal kanıt (Wazuh) --- */}
        <section aria-labelledby="kanit-baslik">
          <Card className="h-full">
            <CardHeader>
              <CardTitle id="kanit-baslik">Orijinal kanıt (Wazuh)</CardTitle>
              <Badge tone="neutral">orijinal veri</Badge>
            </CardHeader>
            <CardContent className="divide-y divide-slate-800/60">
              <EvidenceRow label="Kural ID" value={event.rule_id} />
              <EvidenceRow label="Seviye (orijinal)" value={String(event.rule_level)} />
              <EvidenceRow label="Kural grupları" value={event.rule_groups.join(", ")} />
              <EvidenceRow
                label="Agent"
                value={event.agent_name ? `${event.agent_name} (${event.agent_id ?? "—"})` : null}
              />
              <EvidenceRow label="Manager" value={event.manager} />
              <EvidenceRow label="Konum" value={event.location} />
              <EvidenceRow label="Decoder" value={event.decoder} />
              <EvidenceRow label="Kaynak IP" value={event.src_ip} />
              <EvidenceRow
                label="İlk/son görülme"
                value={`${formatDateTime(event.received_at)} → ${formatDateTime(event.last_seen_at)}`}
              />
              <div className="pt-2">
                <p className="mb-1 text-xs font-medium text-slate-500">Maskelenmiş tam log</p>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-950/80 p-3 font-mono text-xs text-slate-400">
                  {event.full_log_redacted ?? "(log saklanmadı)"}
                </pre>
              </div>
            </CardContent>
          </Card>
        </section>

        {/* --- AI değerlendirmesi (AYRI kart; mor aile) --- */}
        <section aria-labelledby="ai-baslik">
          <Card className="h-full border-violet-800/60 bg-violet-950/10">
            <CardHeader>
              <CardTitle id="ai-baslik" className="text-violet-300">
                Model değerlendirmesi (Qwen3 4B)
              </CardTitle>
              <Badge tone="ai">AI çıktısı — doğrulanmalı</Badge>
            </CardHeader>
            <CardContent>
              {!analysis ? (
                <p className="text-sm text-slate-400">
                  Bu olay henüz analiz edilmedi. Analiz döngüsü kapalıysa operatör
                  açana kadar bekler (WORKER_LOOP_ENABLED).
                </p>
              ) : analysis.status === "analysis_failed" ? (
                <div className="space-y-2">
                  <Badge tone="danger">analiz başarısız</Badge>
                  <p className="text-sm text-slate-400">
                    Model çıktısı şema doğrulamasını geçemedi veya zaman aşımına
                    uğradı; güvenli fallback uygulandı. Bu olay için güvenilir
                    değerlendirme YOKTUR — orijinal Wazuh verisini esas alın.
                  </p>
                  {analysis.error_code ? (
                    <p className="break-all font-mono text-xs text-slate-500">
                      hata: {analysis.error_code}
                      {analysis.error_message ? ` — ${analysis.error_message}` : ""}
                    </p>
                  ) : null}
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={badge?.tone ?? "neutral"}>AI: {badge?.label}</Badge>
                    {analysis.confidence !== null ? (
                      <span className="text-xs text-slate-400">
                        güven: %{Math.round(analysis.confidence * 100)}
                      </span>
                    ) : null}
                    {analysis.requires_human_review ? (
                      <Badge tone="warn">insan incelemesi önerilir</Badge>
                    ) : null}
                  </div>

                  {analysis.summary ? (
                    <div>
                      <p className="mb-1 text-xs font-medium text-violet-300/80">Özet</p>
                      <p className="text-sm leading-relaxed text-slate-200">{analysis.summary}</p>
                    </div>
                  ) : null}

                  {analysis.evidence.length > 0 ? (
                    <div>
                      <p className="mb-1 text-xs font-medium text-violet-300/80">Kanıtlar</p>
                      <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
                        {analysis.evidence.map((item, index) => (
                          <li key={index} className="break-all">
                            {item.field ? (
                              <span className="font-mono text-xs text-slate-500">{item.field}: </span>
                            ) : null}
                            <span className="text-slate-300">{String(item.value)}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}

                  {analysis.alternative_explanations.length > 0 ? (
                    <div>
                      <p className="mb-1 text-xs font-medium text-violet-300/80">
                        Alternatif açıklamalar
                      </p>
                      <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
                        {analysis.alternative_explanations.map((item, index) => (
                          <li key={index}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}

                  {analysis.recommended_next_steps.length > 0 ? (
                    <div>
                      <p className="mb-1 text-xs font-medium text-violet-300/80">
                        Önerilen sonraki adımlar
                      </p>
                      <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
                        {analysis.recommended_next_steps.map((item, index) => (
                          <li key={index}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}

                  <p className="border-t border-violet-900/40 pt-2 text-[11px] text-slate-500">
                    model {analysis.model_tag} · şema v{analysis.prompt_template_version} ·{" "}
                    {analysis.duration_ms} ms · {analysis.retries_used} yeniden deneme ·{" "}
                    {formatDateTime(analysis.finished_at)} UTC
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </section>
      </div>

      {/* --- Müdahale: Faz 07 — yalnızca öneri hazırlığı (dry-run) --- */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Müdahale</CardTitle>
          <Badge tone="neutral">dry-run — simülasyon</Badge>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <Button variant="outline" onClick={() => void router.push("/remediation")}>
            Müdahale önerisi oluştur
          </Button>
          <p className="text-xs text-slate-500">
            Öneri politika motorundan (allowlist + hedef kapsamı + tipli
            parametreler) ve admin onayından geçer; yürütme yalnızca
            SİMÜLASYONdur — model eylem başlatamaz, sistem değişikliği yapan
            kod yolu yoktur.
          </p>
        </CardContent>
      </Card>
    </PanelShell>
  );
}
