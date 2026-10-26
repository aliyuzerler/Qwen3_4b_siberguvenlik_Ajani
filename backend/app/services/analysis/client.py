"""Ollama HTTP istemcisi — sözleşme + gerçek uygulama (Faz 04).

Model API erişimi (phases/04):
- "Model API'si yalnızca iç ağ/localhost üzerinden erişilebilir olsun" →
  base_url kısıtı config doğrulamasında zorlanır (config.py:
  ollama_allow_public_host=false iken yalnızca loopback/özel IP/tek-etiket
  hostname/host.docker.internal kabul edilir).
- Uygulamanın Ollama'ya giden YOLU YALNIZCA şunlardır:
    GET  /api/version  → sağlık yoklaması (check_health)
    GET  /api/tags     → model kurulu mu? (ensure_model)
    POST /api/generate → analiz üretimi (format="json", stream=false)
  Araç çağrısı (tool calling), shell/exec, dosya yükleme YOKTUR — model
  yalnızca metin üretir (phases/04: "Başlangıçta sadece analiz").

Hata eşleme (Aktarım düzeyi — altyapı ailesi):
- Bağlantı/zaman aşımı/5xx      → OllamaUnavailableError (retryable)
- 404 (model bulunamadı)        → OllamaModelMissingError + kurulum talimatı
- diğer 4xx                     → OllamaRequestError (retryable değil)
- 2xx + bozuk UTF-8/bozuk zarf  → OllamaBadPayloadError (retryable)

Credential notu: Ollama yerel/kurum içi varsayımıyla kimliksizdir; istemci
hiçbir secret göndermez veya loglamaz. Kimlikli reverse-proxy gerektiren
kurulumlar Faz 08'de ele alınır.
"""

from __future__ import annotations

import json
from typing import Protocol, runtime_checkable

import httpx

from app.services.analysis.errors import (
    AnalysisError,
    OllamaBadPayloadError,
    OllamaModelMissingError,
    OllamaRequestError,
    OllamaUnavailableError,
)

# POST /api/generate istek gövdesi sabitleri (sözleşme)
GENERATE_PATH = "/api/generate"
VERSION_PATH = "/api/version"
TAGS_PATH = "/api/tags"


@runtime_checkable
class OllamaClient(Protocol):
    """Model erişim sözleşmesi — analyzer yalnızca bu arayüzü görür.

    Mock uygulama (testler) da bu protokolü karşılar; analiz mantığı
    gerçek HTTP'den bağımsız test edilir.
    """

    async def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        model_tag: str,
        temperature: float,
        num_predict: int,
        timeout_seconds: float,
    ) -> str:
        """Tek üretim çağrısı; model çıktı METNİNİ döndürür.

        HTTP/aktarım hatalarında yukarıdaki tipli hataları fırlatır.
        """
        ...

    async def check_health(self) -> None:
        """Servis sağlık yoklaması; erişilemezse OllamaUnavailableError."""
        ...

    async def ensure_model(self, model_tag: str) -> None:
        """Model kurulu mu? Kurulu değilse OllamaModelMissingError
        (mesajda `ollama pull <tag>` talimatı)."""
        ...

    async def aclose(self) -> None:
        """HTTP istemcisini kapatır."""
        ...


def _map_status_error(status_code: int, model_tag: str, body_hint: str) -> AnalysisError:
    """HTTP durum kodunu tipli hataya çevirir (gövde ham haliyle taşınmaz)."""
    if status_code == 404:
        return OllamaModelMissingError(
            f"Model '{model_tag}' Ollama'da yüklü değil. Kurulum: "
            f"`ollama pull {model_tag}` komutunu çalıştırın ve backend'i "
            "yeniden başlatın."
        )
    if 400 <= status_code < 500:
        return OllamaRequestError(
            f"Ollama isteği reddedildi (HTTP {status_code}).{body_hint}"
        )
    return OllamaUnavailableError(
        f"Ollama sunucu hatası (HTTP {status_code}).{body_hint}"
    )


class HttpOllamaClient:
    """Gerçek Ollama REST istemcisi (httpx.AsyncClient)."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._client = client or httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(timeout_seconds),
            # Yerel/iç ağ: proxy değişkenlerine güvenme (beklenmedik dış çıkış olmasın)
            trust_env=False,
        )

    async def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        model_tag: str,
        temperature: float,
        num_predict: int,
        timeout_seconds: float,
    ) -> str:
        payload: dict[str, object] = {
            "model": model_tag,
            "prompt": user_prompt,
            "system": system_prompt,
            # Katı JSON çıktı: geçerlilik oranını yükseltir (Faz 09 ölçümü)
            "format": "json",
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": num_predict,
            },
        }
        try:
            response = await self._client.post(
                GENERATE_PATH,
                json=payload,
                timeout=httpx.Timeout(timeout_seconds),
            )
        except httpx.TimeoutException as exc:
            raise OllamaUnavailableError(
                f"Ollama isteği {timeout_seconds}s içinde tamamlanmadı (zaman aşımı)."
            ) from exc
        except httpx.TransportError as exc:
            raise OllamaUnavailableError(
                "Ollama'ya bağlanılamadı (ağ/bağlantı hatası)."
            ) from exc

        if response.status_code != 200:
            # Gövde ham haliyle loglanmaz/taşınmaz; yalnızca yapısal ipucu
            hint = " Lütfen Ollama servisini ve model tag'ini kontrol edin."
            raise _map_status_error(response.status_code, model_tag, hint)

        return _extract_response_text(response)

    async def check_health(self) -> None:
        try:
            response = await self._client.get(VERSION_PATH)
        except httpx.TimeoutException as exc:
            raise OllamaUnavailableError(
                "Ollama sağlık yoklaması zaman aşımına uğradı."
            ) from exc
        except httpx.TransportError as exc:
            raise OllamaUnavailableError("Ollama'ya ulaşılamadı (kapalı olabilir).") from exc
        if response.status_code != 200:
            raise OllamaUnavailableError(
                f"Ollama sağlık yoklaması başarısız (HTTP {response.status_code})."
            )

    async def ensure_model(self, model_tag: str) -> None:
        try:
            response = await self._client.get(TAGS_PATH)
        except httpx.TimeoutException as exc:
            raise OllamaUnavailableError("Model listesi zaman aşımına uğradı.") from exc
        except httpx.TransportError as exc:
            raise OllamaUnavailableError(
                "Model listesi alınamadı (Ollama'ya ulaşılamadı)."
            ) from exc
        if response.status_code != 200:
            raise OllamaUnavailableError(
                f"Model listesi alınamadı (HTTP {response.status_code})."
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise OllamaBadPayloadError("Model listesi geçerli JSON değil.") from exc
        models = body.get("models") if isinstance(body, dict) else None
        if not isinstance(models, list):
            raise OllamaBadPayloadError("Model listesi beklenmeyen biçimde.")
        for entry in models:
            if isinstance(entry, dict) and entry.get("name") == model_tag:
                return
        raise OllamaModelMissingError(
            f"Model '{model_tag}' Ollama'da yüklü değil. Kurulum: "
            f"`ollama pull {model_tag}` komutunu çalıştırın ve backend'i "
            "yeniden başlatın."
        )

    async def aclose(self) -> None:
        await self._client.aclose()


def _extract_response_text(response: httpx.Response) -> str:
    """2xx zarfından model çıktı metnini çıkarır; bozuk zarfı tipli hataya çevirir.

    Zarf örneği: {"model": "...", "response": "{\"schema_version\": 1, ...}",
    "done": true, ...} — `response` alanı model METNİDİR; JSON'u parse etmek
    analyzer'ın (katı şema) işidir.
    """
    try:
        # Bozuk UTF-8 (test fixture dahil): kesin UTF-8 çözümü; replacement
        # karakteriyle sessiz telafi YOK. Çözülen metin JSON parse girdisidir.
        raw = response.content.decode("utf-8")
        envelope = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise OllamaBadPayloadError(
            "Ollama yanıtı bozuk UTF-8 veya geçersiz zarf JSON'u."
        ) from exc
    if not isinstance(envelope, dict):
        raise OllamaBadPayloadError("Ollama zarfı JSON nesnesi değil.")
    text = envelope.get("response")
    if not isinstance(text, str):
        raise OllamaBadPayloadError(
            "Ollama zarfında 'response' metin alanı yok (beklenmeyen yanıt)."
        )
    return text


def build_ollama_client(base_url: str, *, timeout_seconds: float) -> HttpOllamaClient:
    """Ayarlar Ollama istemcisi üretir (mock yolu YOK — gerçek istemci tek yol)."""
    return HttpOllamaClient(base_url, timeout_seconds=timeout_seconds)


__all__ = [
    "GENERATE_PATH",
    "HttpOllamaClient",
    "OllamaClient",
    "build_ollama_client",
]
