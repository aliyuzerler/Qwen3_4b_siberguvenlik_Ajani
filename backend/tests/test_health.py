"""Health/ready endpoint testleri (Faz 01 kabul + Faz 02 Wazuh bileşeni)."""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from app.core.db import dispose_engine
from app.main import create_app
from app.services.wazuh.errors import WazuhAuthError
from app.services.wazuh.mock_source import MockWazuhAlertSource
from tests.conftest import make_settings


async def test_liveness_returns_ok(client: AsyncClient) -> None:
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_readiness_with_db_up(client: AsyncClient) -> None:
    response = await client.get("/api/v1/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["components"]["database"] == "up"
    # Faz 02/04'e kadar bu bileşenler yapılandırılmamıştır.
    assert body["components"]["wazuh"] == "not_configured"
    assert body["components"]["ollama"] == "not_configured"


async def test_readiness_returns_503_when_db_down(tmp_path: object) -> None:
    # Var olmayan dizin → sqlite açılamaz → readiness "down" raporlamalı.
    application = create_app(
        make_settings(tmp_path, database_url="sqlite+aiosqlite:////nonexistent-ajant-dir/t.db")
    )
    from httpx import ASGITransport

    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        response = await http_client.get("/api/v1/ready")
        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "degraded"
        assert body["components"]["database"] == "down"
    await dispose_engine()


async def test_request_id_header_generated(client: AsyncClient) -> None:
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    assert len(response.headers["X-Request-ID"]) >= 16


async def test_request_id_header_passthrough(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/health", headers={"X-Request-ID": "test-correlation-id-123"}
    )
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "test-correlation-id-123"


# --- Faz 02: Wazuh bileşeni ----------------------------------------------


async def test_ready_reports_wazuh_up_with_mock_source(tmp_path: object) -> None:
    application = create_app(
        make_settings(tmp_path, wazuh_source_mode="mock")
    )
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        response = await http_client.get("/api/v1/ready")
    assert response.status_code == 200
    assert response.json()["components"]["wazuh"] == "up"
    await dispose_engine()


async def test_ready_reports_wazuh_down_on_source_failure(tmp_path: object) -> None:
    application = create_app(
        make_settings(tmp_path, wazuh_source_mode="mock")
    )
    # Sentetik hata enjeksiyonu: health probe yetki hatası dönsün
    application.state.wazuh_source = MockWazuhAlertSource(
        error_queue=[WazuhAuthError("yetki yok (sentetik)")]
    )
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        response = await http_client.get("/api/v1/ready")
    body = response.json()
    assert response.status_code == 200  # wazuh down, genel ready hâlâ 200
    assert body["status"] == "ok"
    assert body["components"]["wazuh"] == "down"
    snapshot = application.state.wazuh_status.snapshot()
    assert snapshot.state == "down"
    assert snapshot.last_error is not None
    assert "sentetik" in snapshot.last_error
    await dispose_engine()


async def test_ready_wazuh_not_configured_without_source(tmp_path: object) -> None:
    application = create_app(make_settings(tmp_path))
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        response = await http_client.get("/api/v1/ready")
    assert response.json()["components"]["wazuh"] == "not_configured"
    await dispose_engine()
