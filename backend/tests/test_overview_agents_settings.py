"""Overview, agents ve settings API testleri (Faz 05)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import status
from httpx import AsyncClient

from app.models.analysis import Analysis
from app.models.event import Event
from tests.conftest import TEST_ADMIN_PASSWORD, login_and_headers

pytestmark = pytest.mark.asyncio


async def _seed_two_events_with_analysis() -> None:
    from app.core.db import get_sessionmaker

    async with get_sessionmaker()() as session:
        for index, (level, assessment) in enumerate(
            [(10, "malicious"), (3, "benign"), (7, None)]
        ):
            event = Event(
                source="wazuh",
                alert_id=f"200.{index}",
                idempotency_key=f"wazuh:200.{index}",
                timestamp=datetime.now(UTC) - timedelta(minutes=index),
                received_at=datetime.now(UTC),
                rule_id="5712",
                rule_level=level,
                rule_description="kural",
                rule_groups=["syslog"],
                agent_id="001",
                agent_name="web-01",
                manager="wazuh-manager",
                fingerprint=uuid.uuid4().hex,
            )
            session.add(event)
            await session.flush()  # event.id üretilir (analiz FK'sı için)
            if assessment is not None:
                session.add(
                    Analysis(
                        event_id=event.id,
                        status="completed",
                        ai_assessment=assessment,  # type: ignore[arg-type]
                        model_tag="qwen3:4b",
                        model_quantization="Q4_K_M",
                        prompt_template_version="v1",
                        prompt_chars=100,
                        context_chars=90,
                        duration_ms=500,
                        retries_used=0,
                        finished_at=datetime.now(UTC),
                    )
                )
        await session.commit()


class TestOverview:
    async def test_overview_shape_and_counts(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await _seed_two_events_with_analysis()
        headers = await login_and_headers(client)
        response = await client.get("/api/v1/overview", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert set(body["components"]) == {"database", "wazuh", "ollama"}
        # Sandbox'ta Ollama erişilemez → "down"; DB kesin "up"
        assert body["components"]["database"] == "up"
        counts = body["counts"]
        assert counts["total_events"] == 3
        assert counts["events_24h"] == 3
        assert counts["analyses_completed"] == 2
        assert counts["pending_analysis"] == 1
        assert body["by_assessment"]["malicious"] == 1
        assert body["by_assessment"]["benign"] == 1
        assert body["by_assessment"]["suspicious"] == 0
        assert len(body["recent"]) == 3
        assert body["model"]["model_tag"] == "qwen3:4b"
        assert body["model"]["policy_mode"] == "observe_only"

    async def test_overview_empty_db(self, client: AsyncClient) -> None:
        headers = await login_and_headers(client)
        body = (await client.get("/api/v1/overview", headers=headers)).json()
        assert body["counts"]["total_events"] == 0
        assert body["recent"] == []


class TestAgents:
    async def test_agents_derived_from_events(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await _seed_two_events_with_analysis()
        headers = await login_and_headers(client)
        response = await client.get("/api/v1/agents", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["total"] == 1
        row = body["items"][0]
        assert row["agent_id"] == "001"
        assert row["agent_name"] == "web-01"
        assert row["event_count"] == 3
        assert row["last_seen"] is not None

    async def test_agents_empty(self, client: AsyncClient) -> None:
        headers = await login_and_headers(client)
        body = (await client.get("/api/v1/agents", headers=headers)).json()
        assert body["items"] == []
        assert body["total"] == 0

    async def test_agents_includes_null_agent_group(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        from app.core.db import get_sessionmaker

        async with get_sessionmaker()() as session:
            session.add(
                Event(
                    source="wazuh",
                    alert_id="300.1",
                    idempotency_key="wazuh:300.1",
                    timestamp=datetime.now(UTC),
                    received_at=datetime.now(UTC),
                    rule_id="100",
                    rule_level=1,
                    rule_description="agent'sız kural",
                    rule_groups=[],
                    fingerprint=uuid.uuid4().hex,
                )
            )
            await session.commit()
        headers = await login_and_headers(client)
        body = (await client.get("/api/v1/agents", headers=headers)).json()
        assert body["total"] == 1
        assert body["items"][0]["agent_id"] is None


class TestSettings:
    async def test_settings_returns_safe_view(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        headers = await login_and_headers(client)
        response = await client.get("/api/v1/settings", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["policy_mode"] == "observe_only"
        assert body["model"]["model_tag"] == "qwen3:4b"
        assert body["retention_days"] == 30
        assert body["redaction"]["enabled"] is True
        assert body["worker"]["loop_enabled"] is False
        # SECRET ASLA dönmez
        body_text = str(body)
        assert "password" not in body_text.lower()
        assert TEST_ADMIN_PASSWORD not in body_text
        assert "test-sadece-sahte-secret" not in body_text

    async def test_settings_blocks_viewer(self, make_client: Any) -> None:
        from sqlalchemy.ext.asyncio import AsyncSession as _AS  # noqa: F401

        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        from app.core.db import get_sessionmaker
        from app.models.user import ROLE_VIEWER, User
        from app.services.security.passwords import hash_password

        async with get_sessionmaker()() as session:
            session.add(
                User(
                    username="izleyici",
                    password_hash=hash_password("parola-izleyici"),
                    role=ROLE_VIEWER,
                    is_active=True,
                )
            )
            await session.commit()
        login = await client.post(
            "/api/v1/auth/login",
            json={"username": "izleyici", "password": "parola-izleyici"},
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        response = await client.get("/api/v1/settings", headers=headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN
