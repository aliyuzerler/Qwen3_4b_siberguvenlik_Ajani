/**
 * API istemcisi (Faz 05).
 *
 * Kimlik modeli: JWT Bearer başlığı (localStorage'da saklanır).
 * Karar ve gerekçe (CSRF sorusu):
 * - Kimlik cookie ile TAŞINMAZ; her istekte Authorization başlığı elle eklenir.
 *   Cookie olmadığı için CSRF vektörü bu modelde uygulanamaz (tarayıcı
 *   otomatik credential eklemez).
 * - XSS'e karşı savunma: React metin kaçışı (dangerouslySetInnerHTML
 *   KULLANILMAZ — testle denetlenir), kısa access TTL (15 dk), panelde
 *   secret gösterilmez. Cookie + CSRF token modeli Faz 08 sertleştirmesinde
 *   yeniden değerlendirilecektir.
 */

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

const ACCESS_KEY = "ajant.access_token";
const REFRESH_KEY = "ajant.refresh_token";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(ACCESS_KEY);
}

export function getRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(REFRESH_KEY);
}

export function storeTokens(access: string, refresh: string): void {
  window.localStorage.setItem(ACCESS_KEY, access);
  window.localStorage.setItem(REFRESH_KEY, refresh);
}

export function clearTokens(): void {
  window.localStorage.removeItem(ACCESS_KEY);
  window.localStorage.removeItem(REFRESH_KEY);
}

let refreshPromise: Promise<boolean> | null = null;

/** Refresh token ile yeni access token dener (tek uçuş; yarış güvenli). */
export async function tryRefresh(): Promise<boolean> {
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
    const refresh = getRefreshToken();
    if (!refresh) return false;
    try {
      const response = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refresh }),
      });
      if (!response.ok) return false;
      const body = (await response.json()) as {
        access_token: string;
        refresh_token: string;
      };
      storeTokens(body.access_token, body.refresh_token);
      return true;
    } catch {
      return false;
    } finally {
      refreshPromise = null;
    }
  })();
  return refreshPromise;
}

async function request<T>(path: string, init: RequestInit, retry = true): Promise<T> {
  const token = getAccessToken();
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  // NOT: /auth/login ve /auth/refresh uçlarının 401'i "oturum doldu" DEĞİLDİR
  // (yanlış parola vb.) — bu uçlarda refresh akışına girilmez, mesaj aynen
  // çağırana iletilir. Refresh akışı yalnızca korumalı API çağrıları içindir.
  const isAuthEndpoint = path.startsWith("/api/v1/auth/");

  if (response.status === 401 && retry && !isAuthEndpoint) {
    const refreshed = await tryRefresh();
    if (refreshed) return request<T>(path, init, false);
    clearTokens();
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.href = "/login?reason=expired";
    }
    throw new ApiError(401, "Oturum süresi doldu.");
  }

  if (response.status === 403) {
    throw new ApiError(403, "Bu işlem için gerekli yetkiniz yok.");
  }
  if (!response.ok) {
    let detail = `İstek başarısız (HTTP ${response.status})`;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      // gövde JSON değilse genel mesaj kalır
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  // Faz 06: korelasyon kuralı toggle (admin; backend audit'e yazar)
  patch: <T>(path: string, body: unknown) =>
    request<T>(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
};
