/** Login sayfası testleri (Faz 05): doğrulama, hata durumu, yükleniyor durumu. */
import { act } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import LoginPage from "@/app/login/page";

const replaceMock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock, push: vi.fn() }),
}));

const fetchMock = vi.fn();
global.fetch = fetchMock as unknown as typeof fetch;

describe("LoginPage", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    replaceMock.mockReset();
    window.localStorage.clear();
  });

  async function fillAndSubmit(user: ReturnType<typeof userEvent.setup>) {
    await user.type(screen.getByLabelText("Kullanıcı adı"), "admin");
    await user.type(screen.getByLabelText("Parola"), "parola-123");
    await user.click(screen.getByRole("button", { name: "Giriş yap" }));
  }

  it("başarılı girişte token saklanır ve panele yönlendirilir", async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: "acc",
          refresh_token: "ref",
          token_type: "bearer",
          expires_in: 900,
        }),
        { status: 200 },
      ),
    );
    await fillAndSubmit(user);
    await waitFor(() => {
      expect(replaceMock).toHaveBeenCalledWith("/");
    });
    expect(window.localStorage.getItem("ajant.access_token")).toBe("acc");
    expect(window.localStorage.getItem("ajant.refresh_token")).toBe("ref");
  });

  it("başarısız girişte genel hata mesajı gösterilir (401)", async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: "Kullanıcı adı veya parola hatalı." }), {
        status: 401,
      }),
    );
    await fillAndSubmit(user);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Kullanıcı adı veya parola hatalı.");
    // Yönlendirme YOK
    expect(replaceMock).not.toHaveBeenCalled();
  });

  it("429'da fren mesajı gösterilir", async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: "Çok fazla deneme." }), { status: 429 }),
    );
    await fillAndSubmit(user);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Çok fazla deneme yaptınız");
  });

  it("gönderim sırasında buton devre dışıdır", async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    let resolveFetch: ((value: Response) => void) | undefined;
    fetchMock.mockReturnValueOnce(
      new Promise<Response>((resolve) => {
        resolveFetch = resolve;
      }),
    );
    await user.type(screen.getByLabelText("Kullanıcı adı"), "admin");
    await user.type(screen.getByLabelText("Parola"), "parola-123");
    await user.click(screen.getByRole("button", { name: "Giriş yap" }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Giriş yapılıyor/ })).toBeDisabled();
    });
    // State güncellemesi act içinde çözülür (React 19 act uyarısı önlenir)
    await act(async () => {
      resolveFetch?.(
        new Response(
          JSON.stringify({
            access_token: "a",
            refresh_token: "r",
            token_type: "bearer",
            expires_in: 1,
          }),
          { status: 200 },
        ),
      );
    });
  });
});
