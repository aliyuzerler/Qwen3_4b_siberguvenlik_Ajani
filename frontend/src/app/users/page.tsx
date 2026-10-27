"use client";

/**
 * Kullanıcı yönetimi (Faz 08): yalnızca admin. Sunucuda rol/aktiflik kararları
 * verilir (server-side authorization); bu sayfa yalnızca arayüz. Parola
 * değeri HİÇBİR koşulda ekranda gösterilmez / loglanmaz.
 *
 * Güvenlik notları (backend /users sözleşmesi):
 * - Kendi hesabını devre dışı bırakamazsınız (409 cannot_disable_self).
 * - Son aktif admin'in rolü düşürülemez / hesabı kapatılamaz (409 last_active_admin).
 * - Kullanıcı silme YOKTUR: is_active=false ile devre dışı bırakma tercih edilir
 *   (audit izi korunur).
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorState, ForbiddenState, LoadingState } from "@/components/states";
import { PanelShell } from "@/components/panel-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ApiError, api } from "@/lib/api";
import type { Role, UserListResponse, UserMutationResponse } from "@/lib/types";

const ROLES: Role[] = ["viewer", "analyst", "admin"];

export default function UsersPage() {
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [formError, setFormError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const users = useQuery({
    queryKey: ["users"],
    queryFn: () => api.get<UserListResponse>("/api/v1/users"),
    retry: false,
  });

  const invalidate = () =>
    void queryClient.invalidateQueries({ queryKey: ["users"] });

  const create = useMutation({
    mutationFn: (body: { username: string; password: string; role: Role }) =>
      api.post<UserMutationResponse>("/api/v1/users", body),
    onSuccess: () => {
      setFormError(null);
      setUsername("");
      setPassword("");
      setRole("viewer");
      invalidate();
    },
    onError: (error) => {
      setFormError(error instanceof ApiError ? error.message : "bilinmeyen hata");
    },
  });

  const update = useMutation({
    mutationFn: (body: { userId: string; payload: { role?: Role; is_active?: boolean } }) =>
      api.patch<UserMutationResponse>(`/api/v1/users/${body.userId}`, body.payload),
    onSuccess: () => {
      setActionError(null);
      invalidate();
    },
    onError: (error) => {
      setActionError(error instanceof ApiError ? error.message : "bilinmeyen hata");
    },
  });

  if (users.isLoading) {
    return (
      <PanelShell>
        <h1 className="mb-4 text-lg font-semibold text-slate-100">Kullanıcılar</h1>
        <LoadingState label="Kullanıcı listesi yükleniyor…" />
      </PanelShell>
    );
  }
  if (users.isError) {
    return (
      <PanelShell>
        <h1 className="mb-4 text-lg font-semibold text-slate-100">Kullanıcılar</h1>
        {users.error instanceof ApiError && users.error.status === 403 ? (
          <ForbiddenState />
        ) : (
          <ErrorState
            message={users.error instanceof Error ? users.error.message : "bilinmeyen hata"}
            onRetry={() => void users.refetch()}
          />
        )}
      </PanelShell>
    );
  }

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    setFormError(null);
    if (password.length < 12) {
      setFormError("Parola en az 12 karakter olmalıdır.");
      return;
    }
    create.mutate({ username, password, role });
  };

  return (
    <PanelShell>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-lg font-semibold text-slate-100">Kullanıcılar</h1>
        <span className="text-xs text-slate-500">
          Rol/aktiflik kararları sunucuda verilir; kullanıcı silme yoktur
          (devre dışı bırakma tercih edilir)
        </span>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Kullanıcı listesi</CardTitle>
            <Badge tone="neutral">{users.data?.total ?? 0} kullanıcı</Badge>
          </CardHeader>
          <CardContent>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500">
                  <th className="pb-2">Kullanıcı</th>
                  <th className="pb-2">Rol</th>
                  <th className="pb-2">Durum</th>
                  <th className="pb-2">Son giriş</th>
                  <th className="pb-2">İşlemler</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {users.data?.items.map((user) => (
                  <tr key={user.id} data-testid="user-row">
                    <td className="py-2 font-mono text-xs text-slate-200">{user.username}</td>
                    <td className="py-2">
                      <select
                        aria-label={`Rol seçimi: ${user.username}`}
                        value={user.role}
                        className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200"
                        onChange={(event) =>
                          update.mutate({
                            userId: user.id,
                            payload: { role: event.target.value as Role },
                          })
                        }
                      >
                        {ROLES.map((option) => (
                          <option key={option} value={option}>
                            {option}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="py-2">
                      {user.is_active ? (
                        <Badge tone="info">aktif</Badge>
                      ) : (
                        <Badge tone="neutral">devre dışı</Badge>
                      )}
                    </td>
                    <td className="py-2 text-xs text-slate-400">
                      {user.last_login_at
                        ? new Date(user.last_login_at).toLocaleString("tr-TR")
                        : "—"}
                    </td>
                    <td className="py-2">
                      {user.is_active ? (
                        <Button
                          variant="outline"
                          data-testid={`disable-${user.username}`}
                          onClick={() =>
                            update.mutate({ userId: user.id, payload: { is_active: false } })
                          }
                        >
                          Devre dışı bırak
                        </Button>
                      ) : (
                        <Button
                          variant="outline"
                          data-testid={`enable-${user.username}`}
                          onClick={() =>
                            update.mutate({ userId: user.id, payload: { is_active: true } })
                          }
                        >
                          Etkinleştir
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {actionError ? (
              <p role="alert" className="mt-3 rounded border border-amber-900/50 bg-amber-950/30 px-3 py-2 text-xs text-amber-300">
                {actionError}
              </p>
            ) : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Yeni kullanıcı</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-3">
              <div>
                <label htmlFor="new-username" className="mb-1 block text-xs text-slate-400">
                  Kullanıcı adı (küçük harf, min 3 karakter)
                </label>
                <Input
                  id="new-username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  required
                  minLength={3}
                  maxLength={64}
                />
              </div>
              <div>
                <label htmlFor="new-password" className="mb-1 block text-xs text-slate-400">
                  Parola (en az 12 karakter)
                </label>
                <Input
                  id="new-password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  minLength={12}
                  maxLength={128}
                />
              </div>
              <div>
                <label htmlFor="new-role" className="mb-1 block text-xs text-slate-400">
                  Rol
                </label>
                <select
                  id="new-role"
                  value={role}
                  onChange={(event) => setRole(event.target.value as Role)}
                  className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-2 text-sm text-slate-200"
                >
                  {ROLES.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </div>
              {formError ? (
                <p role="alert" className="rounded border border-amber-900/50 bg-amber-950/30 px-3 py-2 text-xs text-amber-300">
                  {formError}
                </p>
              ) : null}
              <Button type="submit" disabled={create.isPending}>
                {create.isPending ? "Oluşturuluyor…" : "Kullanıcı oluştur"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </PanelShell>
  );
}
