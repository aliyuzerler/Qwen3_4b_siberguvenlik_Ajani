"""HttpOllamaClient sözleşme testleri (Faz 04) — httpx.MockTransport ile.

Senaryolar (phases/04 doğrulama): başarı, Ollama kapalı (bağlantı hatası),
zaman aşımı, 500, 404 (model yok → kurulum talimatı), 4xx, bozuk UTF-8,
bozuk zarf, response alanı yok. İstek gövdesi sözleşmesi: model tag,
format="json", stream=False, seçenekler, system+prompt.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.services.analysis.client import HttpOllamaClient, build_ollama_client
from app.services.analysis.errors import (
    OllamaBadPayloadError,
    OllamaModelMissingError,
    OllamaRequestError,
    OllamaUnavailableError,
)

BASE_URL = "http://127.0.0.1:11434"


def make_client(handler: Any) -> HttpOllamaClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(base_url=BASE_URL, transport=transport)
    return HttpOllamaClient(BASE_URL, client=http)


def envelope(text: str) -> httpx.Response:
    return httpx.Response(
        200, json={"model": "qwen3:4b", "response": text, "done": True}
    )


async def _generate(client: HttpOllamaClient, **overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "system_prompt": "SİSTEM",
        "user_prompt": "KULLANICI",
        "model_tag": "qwen3:4b",
        "temperature": 0.2,
        "num_predict": 512,
        "timeout_seconds": 5.0,
    }
    kwargs.update(overrides)
    return await client.generate(**kwargs)


class TestGenerateSuccess:
    async def test_returns_response_text(self) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["path"] = request.url.path
            captured["body"] = json.loads(request.content.decode("utf-8"))
            return envelope('{"schema_version": 1}')

        client = make_client(handler)
        raw = await _generate(client)
        assert raw == '{"schema_version": 1}'
        assert captured["path"] == "/api/generate"
        body = captured["body"]
        # Sözleşme: katı JSON modu, stream kapalı, seçenekler iletilir
        assert body["model"] == "qwen3:4b"
        assert body["format"] == "json"
        assert body["stream"] is False
        assert body["system"] == "SİSTEM"
        assert body["prompt"] == "KULLANICI"
        assert body["options"] == {"temperature": 0.2, "num_predict": 512}
        await client.aclose()

    async def test_no_tool_or_shell_parameters_sent(self) -> None:
        """phases/04: araç çağrısı/shell yolu YOK — gövdede tools/functions alanı yok."""
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content.decode("utf-8"))
            return envelope("{}")

        client = make_client(handler)
        await _generate(client)
        body = captured["body"]
        assert "tools" not in body and "functions" not in body and "shell" not in body
        await client.aclose()


class TestTransportErrors:
    async def test_connection_error_maps_to_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        client = make_client(handler)
        with pytest.raises(OllamaUnavailableError) as exc:
            await _generate(client)
        assert exc.value.retryable is True
        await client.aclose()

    async def test_timeout_maps_to_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("slow", request=request)

        client = make_client(handler)
        with pytest.raises(OllamaUnavailableError):
            await _generate(client)
        await client.aclose()

    async def test_http_500_maps_to_unavailable_retryable(self) -> None:
        client = make_client(lambda request: httpx.Response(500, text="boom"))
        with pytest.raises(OllamaUnavailableError) as exc:
            await _generate(client)
        assert exc.value.retryable is True
        assert "500" in exc.value.message
        await client.aclose()


class TestModelMissing:
    async def test_404_maps_to_model_missing_with_install_instruction(self) -> None:
        """phases/04: "model yoksa açık hata/kurulum talimatı ver"."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/generate":
                return httpx.Response(
                    404, json={"error": "model 'qwen3:4b' not found, try pulling it first"}
                )
            raise AssertionError("beklenmeyen yol")

        client = make_client(handler)
        with pytest.raises(OllamaModelMissingError) as exc:
            await _generate(client)
        assert "ollama pull qwen3:4b" in exc.value.message
        assert exc.value.retryable is False
        await client.aclose()

    async def test_ensure_model_present_ok(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/tags"
            return httpx.Response(200, json={"models": [{"name": "qwen3:4b"}]})

        client = make_client(handler)
        await client.ensure_model("qwen3:4b")
        await client.aclose()

    async def test_ensure_model_missing_raises_with_instruction(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"models": [{"name": "llama3:8b"}]})

        client = make_client(handler)
        with pytest.raises(OllamaModelMissingError) as exc:
            await client.ensure_model("qwen3:4b")
        assert "ollama pull qwen3:4b" in exc.value.message
        await client.aclose()


class TestRequestErrors:
    async def test_403_maps_to_request_error_non_retryable(self) -> None:
        client = make_client(lambda request: httpx.Response(403, text="forbidden"))
        with pytest.raises(OllamaRequestError) as exc:
            await _generate(client)
        assert exc.value.retryable is False
        await client.aclose()

    async def test_401_maps_to_request_error(self) -> None:
        client = make_client(lambda request: httpx.Response(401, text="unauthorized"))
        with pytest.raises(OllamaRequestError):
            await _generate(client)
        await client.aclose()


class TestBadPayload:
    async def test_broken_utf8_body_maps_to_bad_payload(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b'{"response": "\xff\xfe\xfa"}')

        client = make_client(handler)
        with pytest.raises(OllamaBadPayloadError) as exc:
            await _generate(client)
        assert exc.value.retryable is True
        await client.aclose()

    async def test_non_json_body_maps_to_bad_payload(self) -> None:
        client = make_client(lambda request: httpx.Response(200, text="<html>proxy</html>"))
        with pytest.raises(OllamaBadPayloadError):
            await _generate(client)
        await client.aclose()

    async def test_missing_response_field_maps_to_bad_payload(self) -> None:
        client = make_client(lambda request: httpx.Response(200, json={"done": True}))
        with pytest.raises(OllamaBadPayloadError):
            await _generate(client)
        await client.aclose()

    async def test_non_string_response_maps_to_bad_payload(self) -> None:
        client = make_client(
            lambda request: httpx.Response(200, json={"response": {"nested": True}})
        )
        with pytest.raises(OllamaBadPayloadError):
            await _generate(client)
        await client.aclose()


class TestHealth:
    async def test_check_health_ok(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/version"
            return httpx.Response(200, json={"version": "0.12.0"})

        client = make_client(handler)
        await client.check_health()
        await client.aclose()

    async def test_check_health_down(self) -> None:
        client = make_client(lambda request: httpx.Response(503, text="down"))
        with pytest.raises(OllamaUnavailableError):
            await client.check_health()
        await client.aclose()

    async def test_factory_builds_client(self) -> None:
        client = build_ollama_client("http://localhost:11434", timeout_seconds=10.0)
        assert isinstance(client, HttpOllamaClient)
        await client.aclose()
