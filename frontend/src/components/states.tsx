/**
 * Paylaşılan durum bileşenleri (Faz 05): Loading / Empty / Error.
 * Her liste/kart bu üç durumu destekler (phases/05: "loading/empty/error
 * states ve erişilebilirlik").
 */

import { Button } from "@/components/ui/button";

export function LoadingState({ label = "Yükleniyor…" }: { label?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center justify-center gap-3 rounded-lg border border-slate-800 bg-slate-900/40 px-4 py-10 text-sm text-slate-400"
    >
      <span
        aria-hidden
        className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-sky-400"
      />
      {label}
    </div>
  );
}

export function EmptyState({
  title,
  hint,
}: {
  title: string;
  hint?: string;
}) {
  return (
    <div
      role="note"
      className="rounded-lg border border-dashed border-slate-700 bg-slate-900/30 px-4 py-10 text-center"
    >
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-red-900/60 bg-red-950/30 px-4 py-6 text-center"
    >
      <p className="text-sm font-medium text-red-300">Bir hata oluştu</p>
      <p className="mt-1 text-xs text-red-400/80">{message}</p>
      {onRetry ? (
        <Button variant="outline" className="mt-3" onClick={onRetry}>
          Yeniden dene
        </Button>
      ) : null}
    </div>
  );
}

/** 403 durumu — yetkisiz erişim ekranı (ayrı kart; hata ile karışmaz). */
export function ForbiddenState() {
  return (
    <div
      role="alert"
      className="rounded-lg border border-amber-900/60 bg-amber-950/30 px-4 py-10 text-center"
    >
      <p className="text-sm font-semibold text-amber-300">Erişim yetkiniz yok</p>
      <p className="mt-1 text-xs text-amber-400/80">
        Bu bölüm yalnızca admin rolüne açıktır.
      </p>
    </div>
  );
}
