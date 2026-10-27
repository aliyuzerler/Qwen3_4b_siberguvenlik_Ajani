"use client";

/**
 * Hesabım (Faz 08): kendi parolasını değiştirme — tüm roller.
 * Önbilgi doğrulaması zorunlu (backend /users/me/password): mevcut parola
 * yanlışsa değişiklik reddedilir. Yeni parola en az 12 karakterdir.
 */

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";

import { PanelShell } from "@/components/panel-shell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ApiError, api } from "@/lib/api";
import type { PasswordChangeResponse } from "@/lib/types";

export default function HesabimPage() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const change = useMutation({
    mutationFn: (body: { current_password: string; new_password: string }) =>
      api.post<PasswordChangeResponse>("/api/v1/users/me/password", body),
    onSuccess: () => {
      setSuccess(true);
      setError(null);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    },
    onError: (err) => {
      setSuccess(false);
      setError(err instanceof ApiError ? err.message : "bilinmeyen hata");
    },
  });

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    setSuccess(false);
    if (newPassword.length < 12) {
      setError("Yeni parola en az 12 karakter olmalıdır.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Yeni parola ve tekrarı eşleşmiyor.");
      return;
    }
    change.mutate({ current_password: currentPassword, new_password: newPassword });
  };

  return (
    <PanelShell>
      <h1 className="mb-4 text-lg font-semibold text-slate-100">Hesabım</h1>

      <div className="max-w-xl">
        <Card>
          <CardHeader>
            <CardTitle>Parola değiştir</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-3">
              <div>
                <label htmlFor="current-password" className="mb-1 block text-xs text-slate-400">
                  Mevcut parola
                </label>
                <Input
                  id="current-password"
                  type="password"
                  value={currentPassword}
                  onChange={(event) => setCurrentPassword(event.target.value)}
                  required
                  autoComplete="current-password"
                />
              </div>
              <div>
                <label htmlFor="new-password-field" className="mb-1 block text-xs text-slate-400">
                  Yeni parola (en az 12 karakter)
                </label>
                <Input
                  id="new-password-field"
                  type="password"
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  required
                  minLength={12}
                  autoComplete="new-password"
                />
              </div>
              <div>
                <label htmlFor="confirm-password" className="mb-1 block text-xs text-slate-400">
                  Yeni parola (tekrar)
                </label>
                <Input
                  id="confirm-password"
                  type="password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  required
                  minLength={12}
                  autoComplete="new-password"
                />
              </div>
              {error ? (
                <p role="alert" data-testid="hesabim-error" className="rounded border border-amber-900/50 bg-amber-950/30 px-3 py-2 text-xs text-amber-300">
                  {error}
                </p>
              ) : null}
              {success ? (
                <p role="status" data-testid="hesabim-success" className="rounded border border-emerald-900/50 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-300">
                  Parolanız güncellendi. Bir sonraki girişte yeni parolanızı kullanın.
                </p>
              ) : null}
              <Button type="submit" disabled={change.isPending}>
                {change.isPending ? "Güncelleniyor…" : "Parolayı değiştir"}
              </Button>
            </form>
          </CardContent>
        </Card>

        <p className="mt-3 text-xs text-slate-500">
          Güvenlik notu: parola değeri sunucuda argon2id ile hash'lenir; panel
          ve loglarda hiçbir koşulda gösterilmez. Adminler kendi parolasını
          yalnızca bu ekrandan (önbilgi doğrulamasıyla) değiştirebilir.
        </p>
      </div>
    </PanelShell>
  );
}
