/** Kullanıcı yönetimi sayfası testleri (Faz 08). */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import UsersPage from "@/app/users/page";

const fetchMock = vi.fn();
global.fetch = fetchMock as unknown as typeof fetch;

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => "/users",
  useParams: () => ({}),
}));

const USERS = {
  items: [
    {
      id: "11111111-1111-1111-1111-111111111111",
      username: "admin",
      role: "admin",
      is_active: true,
      created_at: "2026-10-26T00:00:00Z",
      last_login_at: "2026-10-26T09:00:00Z",
    },
    {
      id: "22222222-2222-2222-2222-222222222222",
      username: "görüntüleyici",
      role: "viewer",
      is_active: false,
      created_at: "2026-10-26T00:00:00Z",
      last_login_at: null,
    },
  ],
  total: 2,
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <UsersPage />
    </QueryClientProvider>,
  );
}

describe("Kullanıcılar sayfası (Faz 08)", () => {
  beforeEach(() => {
    fetchMock.mockReset();
  });

  it("kullanıcı satırlarını rol ve durum rozetleriyle listeler", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(USERS), { status: 200 }),
    );
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByTestId("user-row")).toHaveLength(2);
    });
    expect(screen.getByText("admin", { selector: "td" })).toBeInTheDocument();
    expect(screen.getByText("aktif")).toBeInTheDocument();
    expect(screen.getByText("devre dışı")).toBeInTheDocument();
    // Parola/hash değeri listede asla görünmez
    expect(screen.queryByText(/password/i)).not.toBeInTheDocument();
  });

  it("403'te yetki hatası gösterir (admin-only sayfa)", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: "yetki yok" }), { status: 403 }),
    );
    renderPage();
    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Erişim yetkiniz yok");
    });
  });

  it("zayıf parolada istek göndermeden hata verir", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(USERS), { status: 200 }),
    );
    renderPage();
    await waitFor(() => screen.getAllByTestId("user-row"));
    await userEvent.type(screen.getByLabelText(/Kullanıcı adı/), "yeni-kullanici");
    await userEvent.type(screen.getByLabelText(/^Parola/), "kisa-123");
    await userEvent.click(screen.getByRole("button", { name: "Kullanıcı oluştur" }));
    expect(screen.getByRole("alert")).toHaveTextContent("en az 12 karakter");
    // create isteği ATILMAMIŞ olmalı (yalnızca liste çağrısı var)
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("geçerli form ile kullanıcı oluşturma isteği gönderir", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(USERS), { status: 200 }),
    );
    renderPage();
    await waitFor(() => screen.getAllByTestId("user-row"));
    await userEvent.type(screen.getByLabelText(/Kullanıcı adı/), "analyst-iki");
    await userEvent.type(screen.getByLabelText(/^Parola/), "guclu-parola-12345");
    await userEvent.selectOptions(screen.getByLabelText("Rol"), "analyst");
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          user: { ...USERS.items[0], username: "analyst-iki", role: "analyst" },
        }),
        { status: 201 },
      ),
    );
    await userEvent.click(screen.getByRole("button", { name: "Kullanıcı oluştur" }));
    await waitFor(() => {
      // 1) liste, 2) POST create, 3) invalidateQueries sonrası liste yenileme
      expect(fetchMock).toHaveBeenCalledTimes(3);
    });
    const [, init] = fetchMock.mock.calls[1];
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.username).toBe("analyst-iki");
    expect(body.role).toBe("analyst");
  });
});
