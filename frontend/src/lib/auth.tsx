"use client";

/**
 * Oturum bağlamı (Faz 05) — /auth/me üzerinden güncel kullanıcıyı yükler,
 * çıkışta token'ları temizler. Rol bilgisi yalnızca ARAYÜZ gizlemesi içindir;
 * gerçek yetki kararı backend'de verilir (server-side authorization).
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { createContext, useCallback, useContext, type ReactNode } from "react";

import { api, clearTokens, getAccessToken } from "@/lib/api";
import type { MeResponse, Role } from "@/lib/types";

interface AuthContextValue {
  user: MeResponse | null;
  isLoading: boolean;
  isAdmin: boolean;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  isLoading: false,
  isAdmin: false,
  logout: async () => undefined,
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const router = useRouter();

  const meQuery = useQuery({
    queryKey: ["auth", "me"],
    queryFn: () => api.get<MeResponse>("/api/v1/auth/me"),
    enabled: getAccessToken() !== null,
    retry: false,
    staleTime: 60_000,
  });

  const logout = useCallback(async () => {
    clearTokens();
    queryClient.clear();
    router.push("/login");
  }, [queryClient, router]);

  const value: AuthContextValue = {
    user: meQuery.data ?? null,
    isLoading: meQuery.isLoading,
    isAdmin: (meQuery.data?.role as Role | undefined) === "admin",
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  return useContext(AuthContext);
}
