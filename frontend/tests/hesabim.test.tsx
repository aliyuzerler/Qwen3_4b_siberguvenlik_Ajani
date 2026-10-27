/** Hesabım (parola değiştirme) sayfası testleri (Faz 08). */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import HesabimPage from "@/app/hesabim/page";

const fetchMock = vi.fn();
global.fetch = fetchMock as unknown as typeof fetch;

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => "/hesabim",
  useParams: () => ({}),
}));

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <HesabimPage />
    </QueryClientProvider>,
  );
}

describe("Hesabım sayfası (Faz 08)", () => {
  beforeEach(() => {
    fetchMock.mockReset();
  });

  it("yeni parola ile tekrarı eşleşmiyorsa hata verir ve istek atılmaz", async () => {
    renderPage();
    await userEvent.type(screen.getByLabelText("Mevcut parola"), "eski-parola-1234");
    await userEvent.type(screen.getByLabelText("Yeni parola (en az 12 karakter)"), "yeni-parola-12345");
    await userEvent.type(screen.getByLabelText("Yeni parola (tekrar)"), "farkli-parola-98765");
    await userEvent.click(screen.getByRole("button", { name: "Parolayı değiştir" }));
    expect(screen.getByTestId("hesabim-error")).toHaveTextContent("eşleşmiyor");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("12 karakterden kısa parolada hata verir", async () => {
    renderPage();
    await userEvent.type(screen.getByLabelText("Mevcut parola"), "eski-parola-1234");
    await userEvent.type(screen.getByLabelText("Yeni parola (en az 12 karakter)"), "kisa-123");
    await userEvent.type(screen.getByLabelText("Yeni parola (tekrar)"), "kisa-123");
    await userEvent.click(screen.getByRole("button", { name: "Parolayı değiştir" }));
    expect(screen.getByTestId("hesabim-error")).toHaveTextContent("en az 12 karakter");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("doğru formda /users/me/password ucuna istek gönderir", async () => {
    renderPage();
    await userEvent.type(screen.getByLabelText("Mevcut parola"), "eski-parola-1234");
    await userEvent.type(screen.getByLabelText("Yeni parola (en az 12 karakter)"), "yeni-parola-12345");
    await userEvent.type(screen.getByLabelText("Yeni parola (tekrar)"), "yeni-parola-12345");
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ result: "updated" }), { status: 200 }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Parolayı değiştir" }));
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/v1/users/me/password");
    expect(init.method).toBe("POST");
    expect(screen.getByTestId("hesabim-success")).toHaveTextContent("Parolanız güncellendi");
  });

  it("yanlış önbilgide backend 400 mesajını gösterir", async () => {
    renderPage();
    await userEvent.type(screen.getByLabelText("Mevcut parola"), "yanlis-parola");
    await userEvent.type(screen.getByLabelText("Yeni parola (en az 12 karakter)"), "yeni-parola-12345");
    await userEvent.type(screen.getByLabelText("Yeni parola (tekrar)"), "yeni-parola-12345");
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ detail: "Mevcut parola hatalı.", code: "wrong_current_password" }),
        { status: 400 },
      ),
    );
    await userEvent.click(screen.getByRole("button", { name: "Parolayı değiştir" }));
    await waitFor(() => {
      expect(screen.getByTestId("hesabim-error")).toHaveTextContent("Mevcut parola hatalı");
    });
  });
});
