"""Korelasyon API testleri (Faz 06): RBAC, listeleme/filtreler, detay kanıt
bağlantıları, kural toggle (audit'li), hata durumları ve AI ayrımı."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy import select

from app.core.db import get_sessionmaker
from app.models.correlation import Correlation, CorrelationRule
from app.models.event import Event
from app.models.user import ROLE_ANALYST, ROLE_VIEWER, User
from app.services.correlation.repository import CorrelationRepository
from app.services.security.passwords import hash_password
from app.workers.correlation import run_correlation_cycle
from tests.conftest import TEST_ADMIN_PASSWORD, login_and_headers

pytestmark = pytest.mark.asyncio

NOW = datetime.now(UTC)

XSS_PAYLOAD = '<script>alert(1)</script> <img src=x onerror=alert(1)>'


async def _seed_events_and_correlate(count: int = 6, *, agent_id: str = "001") -> None:
    """Sentetik burst verisi saklar ve korelasyon döngüsünü çalıştırır."""
    maker = get_sessionmaker()
    rows = [
        Event(
            source="wazuh",
            alert_id=f"1792974900.{agent_id}.{i:04d}",
            idempotency_key=f"api-{agent_id}-{i}",
            timestamp=NOW - timedelta(minutes=4, seconds=i * -30),
            rule_id="5710",
            rule_level=10,
            rule_description="sshd: Brute force trying to get access to the system.",
            rule_groups=["syslog", "sshd", "authentication_failed"],
            agent_id=agent_id,
            agent_name="web-server-01" if agent_id == "001" else "db-server-01",
            fingerprint=f"api-fp-{agent_id}-{i}",
        )
        for i in range(count)
    ]
    async with maker() as session, session.begin():
        session.add_all(rows)
    await run_correlation_cycle(
        maker, lookback_seconds=3600.0, max_events=1000, now=NOW
    )


async def _sync_catalog() -> None:
    """make_client lifespan çalıştırmaz; kataloğu elle senkronla."""
    from app.services.correlation.rules import build_default_catalog

    await CorrelationRepository(get_sessionmaker()).sync_rule_catalog(
        build_default_catalog()
    )


async def _create_user(role: str, username: str) -> None:
    async with get_sessionmaker()() as session:
        session.add(
            User(
                username=username,
                password_hash=hash_password(f"parola-{username}"),
                role=role,
                is_active=True,
            )
        )
        await session.commit()


async def _login(client: AsyncClient, username: str) -> dict[str, str]:
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": f"parola-{username}"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


class TestCorrelationListEndpoint:
    async def test_requires_authentication(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/correlations")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_empty_list_for_fresh_panel(self, client: AsyncClient) -> None:
        headers = await login_and_headers(client)
        response = await client.get("/api/v1/correlations", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["items"] == [] and body["total"] == 0

    async def test_viewer_and_analyst_can_list(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await _create_user(ROLE_VIEWER, "izleyici")
        await _create_user(ROLE_ANALYST, "analist")
        await _sync_catalog()
        await _seed_events_and_correlate()
        for username in ("izleyici", "analist"):
            headers = await _login(client, username)
            response = await client.get("/api/v1/correlations", headers=headers)
            assert response.status_code == status.HTTP_200_OK, username
            assert response.json()["total"] >= 1

    async def test_list_carries_rule_version_and_evidence(
        self, client: AsyncClient
    ) -> None:
        headers = await login_and_headers(client)
        await _seed_events_and_correlate()
        response = await client.get("/api/v1/correlations", headers=headers)
        items = response.json()["items"]
        assert items
        for item in items:
            assert item["rule_version"] >= 1  # kural sürümü her satırda
            assert item["rule_name"]
            assert "group_value" in item["evidence"]  # kanıt bağlantıları
            assert item["hit_count"] >= 1
            assert item["window_start"] <= item["window_end"]

    async def test_rule_key_filter(self, client: AsyncClient) -> None:
        headers = await login_and_headers(client)
        await _seed_events_and_correlate()
        response = await client.get(
            "/api/v1/correlations",
            headers=headers,
            params={"rule_key": "failed_login_burst"},
        )
        assert response.json()["total"] >= 1
        assert all(
            item["rule_key"] == "failed_login_burst"
            for item in response.json()["items"]
        )
        empty = await client.get(
            "/api/v1/correlations",
            headers=headers,
            params={"rule_key": "yok_boyle_kural"},
        )
        assert empty.json()["total"] == 0

    async def test_agent_name_filter_via_evidence_links(
        self, client: AsyncClient
    ) -> None:
        headers = await login_and_headers(client)
        await _seed_events_and_correlate(agent_id="001")
        await _seed_events_and_correlate(agent_id="002")
        hit = await client.get(
            "/api/v1/correlations",
            headers=headers,
            params={"agent_name": "web-server-01"},
        )
        miss = await client.get(
            "/api/v1/correlations",
            headers=headers,
            params={"agent_name": "mail-server-09"},
        )
        assert hit.json()["total"] >= 1
        assert miss.json()["total"] == 0

    async def test_pagination_bounds(self, client: AsyncClient) -> None:
        headers = await login_and_headers(client)
        bad = await client.get(
            "/api/v1/correlations", headers=headers, params={"page_size": 101}
        )
        assert bad.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
        bad_page = await client.get(
            "/api/v1/correlations", headers=headers, params={"page": 0}
        )
        assert bad_page.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_xss_payload_passes_through_as_json_string(
        self, client: AsyncClient
    ) -> None:
        maker = get_sessionmaker()
        async with maker() as session, session.begin():
            session.add(
                Event(
                    source="wazuh",
                    alert_id="1792974900.900001",
                    idempotency_key="api-xss-1",
                    timestamp=NOW - timedelta(minutes=1),
                    rule_id="5710",
                    rule_level=10,
                    rule_description="sshd: Brute force",
                    rule_groups=["authentication_failed"],
                    agent_id="999",
                    agent_name=XSS_PAYLOAD,
                    fingerprint="api-xss-fp",
                )
            )
        await _seed_events_and_correlate(count=6, agent_id="999")
        headers = await login_and_headers(client)
        response = await client.get(
            "/api/v1/correlations",
            headers=headers,
            params={"agent_name": XSS_PAYLOAD},
        )
        # Payload JSON string olarak aynen taşınır; backend HTML'e çevirmez.
        assert response.status_code == status.HTTP_200_OK
        assert response.headers["content-type"].startswith("application/json")
        if response.json()["items"]:
            assert XSS_PAYLOAD in response.text


class TestCorrelationDetailEndpoint:
    async def test_detail_includes_linked_events_and_rule(
        self, client: AsyncClient
    ) -> None:
        headers = await login_and_headers(client)
        await _seed_events_and_correlate()
        # Aynı pencere başlangıçlı iki kural tespiti üretilebilir; hedef
        # kuralı filtrele (sıra bağımlılığı olmasın):
        listed = await client.get(
            "/api/v1/correlations",
            headers=headers,
            params={"rule_key": "failed_login_burst"},
        )
        correlation_id = listed.json()["items"][0]["id"]
        response = await client.get(
            f"/api/v1/correlations/{correlation_id}", headers=headers
        )
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["rule_key"] == "failed_login_burst"
        assert body["event_count"] == len(body["events"])  # kanıt bağlantıları tam
        assert body["events"], "bağlı olaylar listelenmeli"
        for event in body["events"]:
            # Her bağlı olayda orijinal kanıt alanları dolu, LLM alanı AYRI nesne:
            assert event["alert_id"] and event["rule_id"]
            assert "analysis" in event  # ayrı nesne; korelasyon şemasında ai_* YOK
            assert not any(
                key.startswith("ai_") for key in body
            ), "korelasyon gövdesinde LLM alanı olmamalı"

    async def test_detail_404(self, client: AsyncClient) -> None:
        headers = await login_and_headers(client)
        response = await client.get(
            "/api/v1/correlations/00000000-0000-0000-0000-000000000000",
            headers=headers,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_malformed_id_422(self, client: AsyncClient) -> None:
        headers = await login_and_headers(client)
        response = await client.get("/api/v1/correlations/not-a-uuid", headers=headers)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


class TestCorrelationRulesEndpoint:
    async def test_catalog_seeded_and_visible_to_viewer(
        self, make_client: Any
    ) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await _create_user(ROLE_VIEWER, "izleyici")
        await _sync_catalog()
        headers = await _login(client, "izleyici")
        response = await client.get("/api/v1/correlation-rules", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        keys = {item["key"] for item in response.json()["items"]}
        assert keys == {
            "failed_login_burst",
            "repeated_alert",
            "suspicious_change_after_login",
        }
        for item in response.json()["items"]:
            assert item["version"] >= 1
            assert item["kind"] in ("burst", "sequence")
            assert item["params"]["window_seconds"] > 0
            assert "secret" not in str(item).lower()  # katalog secret taşımaz


class TestCorrelationRulePatch:
    async def test_admin_can_toggle_and_audit_is_written(
        self, client: AsyncClient
    ) -> None:
        headers = await login_and_headers(client)
        response = await client.patch(
            "/api/v1/correlation-rules/repeated_alert",
            headers=headers,
            json={"enabled": False},
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {
            "key": "repeated_alert",
            "enabled": False,
            "result": "updated",
        }
        async with get_sessionmaker()() as session:
            row = await session.get(CorrelationRule, "repeated_alert")
            from app.models.audit import AuditLog

            entries = (
                await session.scalars(
                    select(AuditLog).where(
                        AuditLog.action == "correlation.rule.updated"
                    )
                )
            ).all()
        assert row is not None and row.enabled is False
        assert len(entries) == 1
        assert entries[0].actor == "admin"
        assert entries[0].detail == {"enabled": False}

    async def test_same_value_is_unchanged_without_audit(
        self, client: AsyncClient
    ) -> None:
        headers = await login_and_headers(client)
        first = await client.patch(
            "/api/v1/correlation-rules/failed_login_burst",
            headers=headers,
            json={"enabled": True},  # zaten açık
        )
        assert first.json()["result"] == "unchanged"
        async with get_sessionmaker()() as session:
            from app.models.audit import AuditLog

            count = len(
                (
                    await session.scalars(
                        select(AuditLog).where(
                            AuditLog.action == "correlation.rule.updated"
                        )
                    )
                ).all()
            )
        assert count == 0

    async def test_unknown_key_404(self, client: AsyncClient) -> None:
        headers = await login_and_headers(client)
        response = await client.patch(
            "/api/v1/correlation-rules/gizli_kural",
            headers=headers,
            json={"enabled": False},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_viewer_and_analyst_forbidden(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await _create_user(ROLE_VIEWER, "izleyici")
        await _create_user(ROLE_ANALYST, "analist")
        for username in ("izleyici", "analist"):
            headers = await _login(client, username)
            response = await client.patch(
                "/api/v1/correlation-rules/repeated_alert",
                headers=headers,
                json={"enabled": False},
            )
            assert response.status_code == status.HTTP_403_FORBIDDEN, username

    async def test_unauthenticated_forbidden(self, client: AsyncClient) -> None:
        response = await client.patch(
            "/api/v1/correlation-rules/repeated_alert", json={"enabled": False}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_invalid_body_422(self, client: AsyncClient) -> None:
        headers = await login_and_headers(client)
        response = await client.patch(
            "/api/v1/correlation-rules/repeated_alert",
            headers=headers,
            json={"enabled": "belki", "extra": 1},  # tip + extra="forbid"
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_disabled_rule_stops_detection_but_stays_listed(
        self, client: AsyncClient
    ) -> None:
        headers = await login_and_headers(client)
        # Kapat → döngü kuralı değerlendirmez; mevcut kural listesi kalır:
        await client.patch(
            "/api/v1/correlation-rules/repeated_alert",
            headers=headers,
            json={"enabled": False},
        )
        await _seed_events_and_correlate()
        listed = await client.get("/api/v1/correlation-rules", headers=headers)
        rules = {item["key"]: item["enabled"] for item in listed.json()["items"]}
        assert rules["repeated_alert"] is False
        async with get_sessionmaker()() as session:
            keys = {
                row.rule_key
                for row in (await session.scalars(select(Correlation))).all()
            }
        assert "repeated_alert" not in keys  # kapalı kural tespit ÜRETMEZ


class TestAnalysisSeparation:
    async def test_llm_comment_stays_on_event_not_correlation(
        self, client: AsyncClient
    ) -> None:
        """Kural çıktısı ↔ LLM yorumu ayrımı (phases/06 gereksinimi)."""
        from app.models.analysis import Analysis

        maker = get_sessionmaker()
        # Olaya bir model kaydı bağla (analyses ayrı tablo):
        async with maker() as session, session.begin():
            event = Event(
                source="wazuh",
                alert_id="1792974900.700001",
                idempotency_key="api-sep-1",
                timestamp=NOW - timedelta(minutes=3),
                rule_id="5710",
                rule_level=10,
                rule_description="sshd: Brute force",
                rule_groups=["authentication_failed"],
                agent_id="777",
                agent_name="web-server-01",
                fingerprint="api-sep-fp",
            )
            session.add(event)
            await session.flush()
            session.add(
                Analysis(
                    event_id=event.id,
                    status="completed",
                    ai_assessment="malicious",
                    confidence=0.9,
                    model_tag="qwen3:4b",
                    model_quantization="Q4_K_M",
                    prompt_template_version="1",
                    prompt_chars=100,
                    context_chars=100,
                    duration_ms=10,
                    finished_at=NOW,
                )
            )
        await _seed_events_and_correlate(count=6, agent_id="777")
        headers = await login_and_headers(client)
        listed = await client.get(
            "/api/v1/correlations", headers=headers, params={"rule_key": "failed_login_burst"}
        )
        assert listed.json()["total"] >= 1
        detail = await client.get(
            f"/api/v1/correlations/{listed.json()['items'][0]['id']}", headers=headers
        )
        body = detail.json()
        # Korelasyon gövdesi SADECE kural çıktısı:
        assert "ai_assessment" not in body and "confidence" not in body
        # LLM yorumu yalnızca olayın analysis nesnesinde:
        linked = next(e for e in body["events"] if e["alert_id"] == "1792974900.700001")
        assert linked["analysis"] is not None
        assert linked["analysis"]["ai_assessment"] == "malicious"
        # Diğer olayların model kaydı yok → analysis null (dürüst gösterim):
        others = [e for e in body["events"] if e["alert_id"] != "1792974900.700001"]
        assert all(e["analysis"] is None for e in others)
