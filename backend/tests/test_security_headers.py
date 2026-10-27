"""Sertleştirme testleri (Faz 08): güvenlik başlıkları, gövde limiti, prod validator'lar.

Kapsam (phases/08: "TLS ve güvenli cookie/header ayarları", "rate limit ve
DoS dayanıklılığı", "üretime geçişte observe-only varsayılanı"):
- Savunmacı yanıt başlıkları her uçta bulunur (401/404 dahil).
- HSTS yalnızca HSTS_ENABLED=true iken eklenir (varsayılan kapalı: TLS
  proxy'de sonlanabilir — çift başlık olmamalı).
- İstek gövdesi tavanı: Content-Length aşımı okunmadan 413; chunked aşımı
  tamponlama sınırında 413.
- APP_ENV=prod: /docs, /redoc, /openapi.json kapalı; localhost CORS yasak;
  WAZUH_VERIFY_TLS=false yasak; POLICY_MODE yalnızca observe_only
  (escape hatch: REMEDIATION_PROD_ALLOW_DRY_RUN).
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import Settings
from app.core.db import dispose_engine
from app.main import create_app
from tests.conftest import make_settings


class TestSecurityHeaders:
    async def test_headers_present_on_public_endpoint(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["cache-control"] == "no-store"
        assert "default-src 'none'" in response.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]

    async def test_headers_present_on_error_responses(self, client: AsyncClient) -> None:
        # 401 (auth yok) ve 404 yanıtlarında da başlıklar mutlaka bulunur.
        for path in ("/api/v1/events", "/api/v1/yok-boyle-uc"):
            response = await client.get(path)
            assert response.status_code in (401, 404)
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"

    async def test_hsts_absent_by_default(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/health")
        assert "strict-transport-security" not in response.headers

    async def test_hsts_present_when_enabled(self, tmp_path: object) -> None:
        application = create_app(make_settings(tmp_path, hsts_enabled=True))
        try:
            transport = ASGITransport(app=application)
            async with AsyncClient(transport=transport, base_url="http://testserver") as http:
                response = await http.get("/api/v1/health")
                assert response.status_code == 200
                hsts = response.headers["strict-transport-security"]
                assert "max-age=31536000" in hsts
                assert "includeSubDomains" in hsts
        finally:
            await dispose_engine()


class TestBodySizeLimit:
    async def test_oversized_content_length_rejected_413(self, tmp_path: object) -> None:
        # Tavan küçültülmüş uygulama: 1 KB üstü reddedilir.
        application = create_app(make_settings(tmp_path, max_request_body_bytes=1024))
        try:
            transport = ASGITransport(app=application)
            async with AsyncClient(transport=transport, base_url="http://testserver") as http:
                response = await http.post(
                    "/api/v1/auth/login", json={"username": "x", "password": "y" * 4096}
                )
                assert response.status_code == 413
                assert response.json()["error"] == "request_too_large"
        finally:
            await dispose_engine()

    async def test_normal_body_accepted(self, client: AsyncClient) -> None:
        # Tavan altındaki gövdeler etkilenmez (400/401 iş mantığı yolu).
        response = await client.post(
            "/api/v1/auth/login", json={"username": "yok", "password": "yok"}
        )
        assert response.status_code == 401

    async def test_chunked_oversized_body_rejected_413(self, tmp_path: object) -> None:
        # Content-Length'siz (chunked) gövde: tamponlama aşımında 413.
        application = create_app(make_settings(tmp_path, max_request_body_bytes=512))
        try:
            transport = ASGITransport(app=application)

            async def stream_bytes() -> AsyncClient:
                # httpx content iterator: parça parça 2 KB gönderilir
                for _ in range(4):
                    yield b"x" * 512

            async with AsyncClient(transport=transport, base_url="http://testserver") as http:
                response = await http.post(
                    "/api/v1/auth/login",
                    content=stream_bytes(),
                    headers={"Content-Type": "application/json"},
                )
                assert response.status_code == 413
        finally:
            await dispose_engine()

    async def test_invalid_content_length_rejected_400(self, tmp_path: object) -> None:
        application = create_app(make_settings(tmp_path))
        try:
            transport = ASGITransport(app=application)
            async with AsyncClient(transport=transport, base_url="http://testserver") as http:
                response = await http.post(
                    "/api/v1/auth/login",
                    content=b"{}",
                    headers={"Content-Type": "application/json", "Content-Length": "abc"},
                )
                assert response.status_code == 400
                assert response.json()["error"] == "invalid_content_length"
        finally:
            await dispose_engine()


class TestProdHardening:
    def _prod_settings(self, tmp_path: object, **overrides: object) -> Settings:
        return make_settings(
            tmp_path,
            app_env="prod",
            cors_origins="https://panel.example.internal",
            **overrides,
        )

    def test_prod_observe_only_enforced(self, tmp_path: object) -> None:
        with pytest.raises(Exception, match="observe_only"):
            self._prod_settings(tmp_path, policy_mode="dry_run")

    def test_prod_dry_run_requires_explicit_escape_hatch(self, tmp_path: object) -> None:
        # İki bağımsız kapı: dry_run + escape hatch birlikte açık olmalı.
        settings = self._prod_settings(
            tmp_path, policy_mode="dry_run", remediation_prod_allow_dry_run=True
        )
        assert settings.policy_mode == "dry_run"

    def test_prod_rejects_localhost_cors(self, tmp_path: object) -> None:
        with pytest.raises(Exception, match="CORS"):
            make_settings(tmp_path, app_env="prod", cors_origins="http://localhost:3000")

    def test_prod_rejects_disabled_wazuh_tls_verification(self, tmp_path: object) -> None:
        with pytest.raises(Exception, match="WAZUH_VERIFY_TLS"):
            self._prod_settings(tmp_path, wazuh_verify_tls=False)

    def test_prod_policy_mode_default_is_observe_only(self, tmp_path: object) -> None:
        settings = self._prod_settings(tmp_path)
        assert settings.policy_mode == "observe_only"

    async def test_prod_disables_docs_endpoints(self, tmp_path: object) -> None:
        application = create_app(self._prod_settings(tmp_path))
        try:
            transport = ASGITransport(app=application)
            async with AsyncClient(transport=transport, base_url="http://testserver") as http:
                for path in ("/docs", "/redoc", "/openapi.json"):
                    response = await http.get(path)
                    assert response.status_code == 404, f"{path} prod'da kapalı olmalı"
        finally:
            await dispose_engine()

    async def test_dev_keeps_docs_enabled(self, client: AsyncClient) -> None:
        response = await client.get("/openapi.json")
        assert response.status_code == 200
