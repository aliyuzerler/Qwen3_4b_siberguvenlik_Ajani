"use client";

/**
 * Giriş sayfası (Faz 05): kullanıcı adı + parola → /auth/login.
 * Hata durumu genel mesaj gösterir (kullanıcı/parola ayrımı sızdırılmaz).
 */

import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { ApiError, api, getAccessToken, storeTokens } from "@/lib/api";
import type { TokenResponse } from "@/lib/types";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const tokens = await api.post<TokenResponse>("/api/v1/auth/login", {
        username,
        password,
      });
      storeTokens(tokens.access_token, tokens.refresh_token);
      router.replace("/");
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError("Çok fazla deneme yaptınız. Lütfen birazdan tekrar deneyin.");
      } else {
        setError(err instanceof Error ? err.message : "Giriş yapılamadı.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  // Zaten oturum açıksa ana sayfaya (client-side; SSR'da no-op)
  if (getAccessToken()) {
    router.replace("/");
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm rounded-lg border border-slate-800 bg-slate-900/60 p-6">
        <div className="mb-6 text-center">
          <span className="rounded bg-sky-500/15 px-2 py-1 text-xs font-bold tracking-wide text-sky-400">
            ajant
          </span>
          <h1 className="mt-3 text-lg font-semibold text-slate-100">
            Güvenlik Paneli Girişi
          </h1>
          <p className="mt-1 text-xs text-slate-500">
            Wazuh + Qwen3 4B güvenlik ajanı (yalnızca gözlem modu)
          </p>
        </div>
        <form onSubmit={onSubmit} className="space-y-4" noValidate>
          <div>
            <Label htmlFor="username">Kullanıcı adı</Label>
            <Input
              id="username"
              name="username"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              disabled={submitting}
            />
          </div>
          <div>
            <Label htmlFor="password">Parola</Label>
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={submitting}
            />
          </div>
          {error ? (
            <p role="alert" className="rounded border border-red-900/60 bg-red-950/40 px-3 py-2 text-xs text-red-300">
              {error}
            </p>
          ) : null}
          <Button type="submit" className="w-full" disabled={submitting || !username || !password}>
            {submitting ? "Giriş yapılıyor…" : "Giriş yap"}
          </Button>
        </form>
      </div>
    </main>
  );
}
