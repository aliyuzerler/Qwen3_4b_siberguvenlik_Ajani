#!/usr/bin/env python3
"""Sahte Ollama sunucusu — Faz 10 fallback test düzeneği.

GERÇEK model DEĞİLDİR: /api/generate her çağrıda SABİT, geçersiz model
çıktısı (JSON olmayan metin) döndürür. Amacı, gerçek Ollama olmadan
`analysis_failed` (güvenli fallback) yolunu UÇTAN UCA kanıtlamaktır
(phases/10 test promptu: "Model/Ollama kapalıyken sistemin güvenli
fallback verdiğini kontrol et").

Yalnızca test/staging amaçlıdır; üretimde KULLANILMAZ. Yanıt sözleşmesi
backend/app/services/analysis/client.py ile birebir uyumludur:

- GET  /api/version  → {"version": "0.0.0-smoke-fake"}          (sağlık)
- GET  /api/tags     → {"models": [{"name": <model_tag>}]}      (model kurulu)
- POST /api/generate → {"response": "<geçerli zarf, geçersiz model JSON'u>"}

Zarf geçerli olduğundan istemci transport hatası DEĞİL, model METNİ alır;
katı şema doğrulaması (analyzer) çıktıyı reddeder → retry → analysis_failed.
Bu, "model yanıt veriyor ama çıktısı geçersiz" senaryosunun deterministik
simülasyonudur.

Kullanım:
    python3 scripts/fake_ollama_server.py --port 11450

Ortam değişkenleri:
    FAKE_MODEL_TAG   (varsayılan qwen3:4b) — /api/tags'ta raporlanan model
"""
from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Geçersiz model çıktısı: analyzer'ın katı şemasını bilinçli İHLAL eder.
# Not: prompt injection komutu DEĞİLDİR — yalnızca parse edilemez metin.
INVALID_MODEL_OUTPUT = (
    "Elbette yardımcı olayım! İşte analiz sonucu: bu metin geçerli bir JSON "
    "nesnesi değildir; şema doğrulaması bunu reddetmelidir."
)


def build_handler(model_tag: str) -> type[BaseHTTPRequestHandler]:
    class FakeOllamaHandler(BaseHTTPRequestHandler):
        def _send_json(self, status: int, body: dict[str, object]) -> None:
            payload = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 — http.server adı
            if self.path == "/api/version":
                self._send_json(200, {"version": "0.0.0-smoke-fake"})
            elif self.path == "/api/tags":
                self._send_json(200, {"models": [{"name": model_tag}]})
            else:
                self._send_json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802 — http.server adı
            if self.path != "/api/generate":
                self._send_json(404, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > 0:
                self.rfile.read(length)  # istek gövdesini tüket (sözleşme gereği)
            # 200 + GEÇERLİ zarf + GEÇERSİZ model çıktısı (fallback yolu)
            self._send_json(200, {"model": model_tag, "response": INVALID_MODEL_OUTPUT,
                                  "done": True})

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            # Test düzeneği: istek loglarını sessize al (smoke çıktısı temiz kalsın)
            pass

    return FakeOllamaHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="Sahte Ollama (test düzeneği)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=11450)
    args = parser.parse_args()

    model_tag = os.environ.get("FAKE_MODEL_TAG", "qwen3:4b")
    server = ThreadingHTTPServer((args.host, args.port), build_handler(model_tag))
    print(f"[fake_ollama] {args.host}:{args.port} dinliyor (model_tag={model_tag}, "
          "yanıtlar bilinçli GEÇERSİZ)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
