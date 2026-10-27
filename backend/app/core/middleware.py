"""İstek ara katmanları (Faz 01 request-id → Faz 08 sertleştirme).

RequestIdMiddleware : her isteğe benzersiz X-Request-ID (izlenebilirlik).
SecurityHeadersMiddleware : API yanıtlarına savunmacı başlıklar (Faz 08):
    - X-Content-Type-Options: nosniff  → MIME koklamayı kapatır
    - X-Frame-Options: DENY           → clickjacking yüzeyini kapatır
    - Referrer-Policy: no-referrer    → iç yolların dışarı sızmaması
    - Cache-Control: no-store         → kimlikli yanıtlar önbelleğe girmez
    - Content-Security-Policy: default-src 'none' (bu bir JSON API'sidir;
      HTML sunmaz — dokümantasyon UI'si /docs prod'da kapalıdır)
    - Strict-Transport-Security yalnızca HSTS_ENABLED=true iken eklenir
      (TLS uygulamanın önünde sonlanmıyorsa proxy sorumludur).
BodySizeLimitMiddleware : istek gövdesi tavanı (DoS dayanıklılığı, Faz 08):
    - Content-Length başlığı tavanı aşarsa gövde okunmadan 413 döner.
    - Content-Length yoksa (chunked) gövde tavanla tamponlanır; aşım anında
      413 döner (bellek tavanla sınırlıdır).
Cookie/CSRF kararı (Faz 08 yeniden değerlendirmesi): kimlik Bearer başlığı
ile taşınır (cookie oturumu YOK) → CSRF vektörü bu modelde uygulanamaz;
karar + gerekçe docs/phase-05-verification.md ve docs/phase-08-verification.md.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

import structlog
from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUEST_ID_HEADER = "X-Request-ID"

# Yanıtta content-length görünümlü başlıkları ÇAKIŞMADAN ezmek için
# setdefault kullanılır (uvicorn zaten content-length yazar).
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}

HSTS_HEADER_VALUE = "max-age=31536000; includeSubDomains"


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.clear_contextvars()
        response.headers[REQUEST_ID_HEADER] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Tüm yanıtlara savunmacı başlıklar ekler (Faz 08: güvenli header ayarları)."""

    def __init__(self, app: ASGIApp, *, hsts_enabled: bool = False) -> None:
        super().__init__(app)
        self._hsts_enabled = hsts_enabled

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if self._hsts_enabled:
            response.headers.setdefault("Strict-Transport-Security", HSTS_HEADER_VALUE)
        return response


def _reject_response(status: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": code})


class BodySizeLimitMiddleware:
    """İstek gövdesi tavanı (saf ASGI middleware'i; Faz 08: DoS dayanıklılığı).

    - Content-Length tavanı aşıyorsa istek OKUNMADAN reddedilir (ucuz yol).
    - Content-Length yoksa gövde tavanla tamponlanır; tavan aşılınca 413
      döner ve kalan baytlar okunmaz (bellek kullanımı tavanla sınırlı).
    - Yönlendirici olmayan istekler (GET vb. gövdesiz) dokunulmadan geçer.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        raw_length = headers.get("content-length")
        if raw_length is not None:
            try:
                declared = int(raw_length)
            except ValueError:
                await _reject_response(400, "invalid_content_length")(scope, receive, send)
                return
            if declared > self._max_bytes:
                await _reject_response(413, "request_too_large")(scope, receive, send)
                return
            await self.app(scope, receive, send)
            return

        # Chunked / Content-Length'siz gövde: tavanla tamponla.
        buffered = bytearray()
        overflow = False
        while True:
            message: Message = await receive()
            if message["type"] == "http.request":
                buffered.extend(message.get("body", b""))
                if len(buffered) > self._max_bytes:
                    overflow = True
                    break
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                return
        if overflow:
            await _reject_response(413, "request_too_large")(scope, receive, send)
            return

        # Tamponlanan gövdeyi uygulamaya tek parça geri oynat.
        replayed = bytes(buffered)
        consumed = False

        async def replay_receive() -> Message:
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": replayed, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)
