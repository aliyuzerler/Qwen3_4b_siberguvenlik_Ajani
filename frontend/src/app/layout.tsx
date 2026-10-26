import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ajant — Güvenlik Paneli",
  description:
    "Wazuh + Qwen3 4B güvenlik olayları analiz paneli (yalnızca gözlem modu)",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="tr">
      <body>{children}</body>
    </html>
  );
}
