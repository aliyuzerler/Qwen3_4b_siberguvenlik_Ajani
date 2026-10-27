"use client";

/**
 * Panel kabuğu (Faz 05): navigasyon + üst çubuk + oturum koruması.
 * Koruma NOTU: bu guard kullanıcı deneyimi içindir; yetki kararı
 * backend'de verilir (401/403 yanıtları API katmanında zorlanır).
 */

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { getAccessToken } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";

const NAV_ITEMS: { href: string; label: string; adminOnly?: boolean }[] = [
  { href: "/", label: "Genel Bakış" },
  { href: "/events", label: "Olaylar" },
  { href: "/correlations", label: "Korelasyon" },
  { href: "/rules", label: "Kurallar" },
  { href: "/agents", label: "Sunucular" },
  { href: "/audit", label: "Audit Log", adminOnly: true },
  { href: "/settings", label: "Ayarlar", adminOnly: true },
];

export function PanelShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { user, isAdmin, logout, isLoading } = useAuth();

  useEffect(() => {
    // Token yoksa giriş ekranına yönlendir (client-side UX guard)
    if (!isLoading && !getAccessToken()) {
      router.replace("/login");
    }
  }, [isLoading, router]);

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-slate-400">
        <span
          aria-hidden
          className="mr-3 h-5 w-5 animate-spin rounded-full border-2 border-slate-700 border-t-sky-400"
        />
        Oturum kontrol ediliyor…
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 bg-slate-950/90">
        <div className="mx-auto flex max-w-7xl items-center gap-6 px-4 py-3">
          <Link href="/" className="flex items-center gap-2">
            <span className="rounded bg-sky-500/15 px-2 py-1 text-xs font-bold tracking-wide text-sky-400">
              ajant
            </span>
            <span className="text-sm font-semibold text-slate-200">
              Güvenlik Paneli
            </span>
            <span className="ml-1 rounded border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
              observe_only
            </span>
          </Link>
          <nav aria-label="Ana menü" className="flex flex-1 items-center gap-1">
            {NAV_ITEMS.filter((item) => !item.adminOnly || isAdmin).map((item) => (
              <Link
                key={item.href}
                href={item.href}
                aria-current={pathname === item.href ? "page" : undefined}
                className={cn(
                  "rounded-md px-3 py-1.5 text-sm",
                  pathname === item.href
                    ? "bg-slate-800 font-medium text-slate-100"
                    : "text-slate-400 hover:bg-slate-900 hover:text-slate-200",
                )}
              >
                {item.label}
              </Link>
            ))}
          </nav>
          {user ? (
            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-400">
                <span className="font-medium text-slate-200">{user.username}</span>{" "}
                · {user.role}
              </span>
              <Button variant="outline" onClick={() => void logout()}>
                Çıkış
              </Button>
            </div>
          ) : null}
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6">{children}</main>
      <footer className="mx-auto max-w-7xl px-4 pb-8 pt-2 text-[11px] text-slate-600">
        ajant — yalnızca gözlem modu (Faz 07'ye kadar hiçbir müdahale yolu yoktur) ·
        Model: Qwen3 4B (Ollama, yerel)
      </footer>
    </div>
  );
}
