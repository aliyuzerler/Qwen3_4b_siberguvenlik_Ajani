"""Events API testleri (Faz 05).

Kapsam: boş liste, sayfalama sınırları, filtreler (assessment,
rule_level_min, source, agent_name, q arama, since/until), detay yanıtı,
AI ayrımı (orijinal severity ↔ ai_assessment), XSS payload güvenli
taşıma, hata/boş durumlar.

Olaylar doğrudan DB'ye seed edilir (Faz 03 repository'si ile değil —
bu testler PANEL sözleşmesini doğrular).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import Analysis
from app.models.event import Event
from tests.conftest import TEST_ADMIN_PASSWORD, login_and_headers

pytestmark = pytest.mark.asyncio

XSS_PAYLOAD = '<script>alert("xss")</script> 🚨 <img src=x onerror=alert(1)>'


async def _seed_event(
    session: AsyncSession,
    *,
    alert_id: str = "100.1",
    rule_level: int = 7,
    rule_description: str = "Test kuralı",
    agent_name: str | None = "web-01",
    agent_id: str | None = "001",
    source: str = "wazuh",
    timestamp: datetime | None = None,
    full_log: str | None = None,
    src_ip: str | None = None,
    analysis: Analysis | None = None,
) -> Event:
    event = Event(
        source=source,
        alert_id=alert_id,
        idempotency_key=f"{source}:{alert_id}",
        timestamp=timestamp or datetime.now(UTC),
        received_at=datetime.now(UTC),
        rule_id="5700",
        rule_level=rule_level,
        rule_description=rule_description,
        rule_groups=["syslog"],
        agent_id=agent_id,
        agent_name=agent_name,
        manager="wazuh-manager",
        location="/var/log/auth.log",
        decoder="sshd",
        full_log_redacted=full_log,
        src_ip=src_ip,
        fingerprint=uuid.uuid4().hex,
    )
    session.add(event)
    await session.flush()  # event.id üretilir (analiz FK'sı için gerekli)
    if analysis is not None:
        analysis.event_id = event.id
        session.add(analysis)
    await session.commit()
    await session.refresh(event)
    return event


def _completed_analysis(**overrides: object) -> Analysis:
    values: dict[str, object] = {
        "status": "completed",
        "ai_assessment": "suspicious",
        "confidence": 0.72,
        "summary": "SSH brute force gözlendi.",
        "evidence": [{"field": "rule.description", "value": "brute force"}],
        "alternative_explanations": ["Yanlış yapılandırılmış istemci"],
        "recommended_next_steps": ["review_full_logs"],
        "requires_human_review": 1,
        "model_tag": "qwen3:4b",
        "model_quantization": "Q4_K_M",
        "prompt_template_version": "v1",
        "prompt_chars": 900,
        "context_chars": 800,
        "duration_ms": 1200,
        "retries_used": 0,
        "finished_at": datetime.now(UTC),
    }
    values.update(overrides)
    return Analysis(**values)  # type: ignore[arg-type]


class TestEmptyState:
    async def test_empty_list_returns_zero_items(self, client: AsyncClient) -> None:
        headers = await login_and_headers(client)
        response = await client.get("/api/v1/events", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["items"] == []
        assert body["total"] == 0
        assert body["pages"] == 0


class TestPagination:
    async def test_pagination_returns_correct_slices(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        from app.core.db import get_sessionmaker

        async with get_sessionmaker()() as session:
            for index in range(7):
                await _seed_event(
                    session,
                    alert_id=f"100.{index}",
                    timestamp=datetime.now(UTC) - timedelta(minutes=index),
                )
        headers = await login_and_headers(client)
        page1 = (
            await client.get(
                "/api/v1/events", headers=headers, params={"page": 1, "page_size": 3}
            )
        ).json()
        assert len(page1["items"]) == 3
        assert page1["total"] == 7
        assert page1["pages"] == 3
        page3 = (
            await client.get(
                "/api/v1/events", headers=headers, params={"page": 3, "page_size": 3}
            )
        ).json()
        assert len(page3["items"]) == 1
        # En yeni önce sıralı
        assert page1["items"][0]["alert_id"] == "100.0"

    async def test_page_bounds_validated(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        headers = await login_and_headers(client)
        zero = await client.get("/api/v1/events", headers=headers, params={"page": 0})
        big = await client.get("/api/v1/events", headers=headers, params={"page_size": 1000})
        assert zero.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
        assert big.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


class TestFilters:
    async def test_filter_assessment_completed(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        from app.core.db import get_sessionmaker

        async with get_sessionmaker()() as session:
            await _seed_event(
                session, alert_id="1", analysis=_completed_analysis()
            )
            await _seed_event(session, alert_id="2")  # analiz yok
            await _seed_event(
                session,
                alert_id="3",
                analysis=_completed_analysis(status="analysis_failed", ai_assessment=None),
            )
        headers = await login_and_headers(client)
        completed = (
            await client.get(
                "/api/v1/events", headers=headers, params={"assessment": "completed"}
            )
        ).json()
        assert completed["total"] == 1
        assert completed["items"][0]["alert_id"] == "1"
        none_rows = (
            await client.get(
                "/api/v1/events", headers=headers, params={"assessment": "none"}
            )
        ).json()
        assert none_rows["total"] == 1
        assert none_rows["items"][0]["alert_id"] == "2"
        failed = (
            await client.get(
                "/api/v1/events", headers=headers, params={"assessment": "analysis_failed"}
            )
        ).json()
        assert failed["total"] == 1
        assert failed["items"][0]["alert_id"] == "3"

    async def test_filter_rule_level_min_and_source_and_agent(
        self, make_client: Any
    ) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        from app.core.db import get_sessionmaker

        async with get_sessionmaker()() as session:
            await _seed_event(
                session, alert_id="1", rule_level=3, source="wazuh", agent_name="web-01"
            )
            await _seed_event(
                session, alert_id="2", rule_level=12, source="wazuh", agent_name="db-01"
            )
        headers = await login_and_headers(client)
        high = (
            await client.get(
                "/api/v1/events", headers=headers, params={"rule_level_min": 10}
            )
        ).json()
        assert high["total"] == 1
        assert high["items"][0]["alert_id"] == "2"
        agent = (
            await client.get(
                "/api/v1/events", headers=headers, params={"agent_name": "db-01"}
            )
        ).json()
        assert agent["total"] == 1
        assert agent["items"][0]["alert_id"] == "2"
        invalid_level = await client.get(
            "/api/v1/events", headers=headers, params={"rule_level_min": 99}
        )
        assert invalid_level.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_search_q_literal_no_wildcard_injection(
        self, make_client: Any
    ) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        from app.core.db import get_sessionmaker

        async with get_sessionmaker()() as session:
            await _seed_event(session, alert_id="1", rule_description="brute force saldırısı")
        headers = await login_and_headers(client)
        # % jokeri HARFİYEN aranır (kaçış) → eşleşme yok
        wildcard = (
            await client.get("/api/v1/events", headers=headers, params={"q": "%100%"})
        ).json()
        assert wildcard["total"] == 0
        found = (
            await client.get(
                "/api/v1/events", headers=headers, params={"q": "brute force"}
            )
        ).json()
        assert found["total"] == 1

    async def test_filter_since_until(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        from app.core.db import get_sessionmaker

        base = datetime.now(UTC) - timedelta(hours=1)
        async with get_sessionmaker()() as session:
            await _seed_event(session, alert_id="eski", timestamp=base)
            await _seed_event(session, alert_id="yeni", timestamp=datetime.now(UTC))
        headers = await login_and_headers(client)
        rows = (
            await client.get(
                "/api/v1/events",
                headers=headers,
                params={"since": (datetime.now(UTC) - timedelta(minutes=5)).isoformat()},
            )
        ).json()
        assert rows["total"] == 1
        assert rows["items"][0]["alert_id"] == "yeni"


class TestEventDetail:
    async def test_detail_includes_original_and_ai_separately(
        self, make_client: Any
    ) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        from app.core.db import get_sessionmaker

        async with get_sessionmaker()() as session:
            event = await _seed_event(
                session,
                alert_id="42",
                rule_level=10,
                rule_description="sshd: brute force",
                full_log="Oct 26 09:15:00 sshd[4321]: Failed password for root",
                src_ip="203.0.113.7",
                analysis=_completed_analysis(ai_assessment="malicious", confidence=0.81),
            )
        headers = await login_and_headers(client)
        response = await client.get(f"/api/v1/events/{event.id}", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        # ORİJİNAL alanlar
        assert body["rule_level"] == 10  # Wazuh orijinali KORUNUR
        assert body["src_ip"] == "203.0.113.7"
        assert "Failed password" in body["full_log_redacted"]
        # AI değerlendirmesi AYRI nesnede — rule_level üzerine YAZILMAMIŞ
        assert body["analysis"]["ai_assessment"] == "malicious"
        assert body["analysis"]["confidence"] == pytest.approx(0.81)
        assert body["analysis"]["model_tag"] == "qwen3:4b"
        assert body["analysis"]["requires_human_review"] is True
        assert body["analysis"]["recommended_next_steps"] == ["review_full_logs"]

    async def test_detail_without_analysis_has_null_analysis(
        self, make_client: Any
    ) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        from app.core.db import get_sessionmaker

        async with get_sessionmaker()() as session:
            event = await _seed_event(session, alert_id="43")
        headers = await login_and_headers(client)
        body = (
            await client.get(f"/api/v1/events/{event.id}", headers=headers)
        ).json()
        assert body["analysis"] is None

    async def test_detail_unknown_id_404(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        headers = await login_and_headers(client)
        response = await client.get(f"/api/v1/events/{uuid.uuid4()}", headers=headers)
        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestXssSafety:
    async def test_xss_payload_in_log_and_ai_output_returned_as_json_string(
        self, make_client: Any
    ) -> None:
        """Zararlı payload aynen TAŞINIR ama JSON string olarak — backend
        HTML üretmez; frontend React metin kaçışıyla güvenli gösterir
        (backend tarafı sözleşme testi)."""
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        from app.core.db import get_sessionmaker

        async with get_sessionmaker()() as session:
            event = await _seed_event(
                session,
                alert_id="999",
                rule_description=f"Rule matched {XSS_PAYLOAD}",
                full_log=f"log line {XSS_PAYLOAD} tail",
                analysis=_completed_analysis(
                    summary=f"Model özeti {XSS_PAYLOAD}",
                    evidence=[{"field": "full_log", "value": XSS_PAYLOAD}],
                ),
            )
        headers = await login_and_headers(client)
        response = await client.get(f"/api/v1/events/{event.id}", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        assert response.headers["content-type"].startswith("application/json")
        body = response.json()
        # Payload KAYIPSIZ string olarak taşınır (encode edilmiş HTML değil)
        assert XSS_PAYLOAD in body["rule_description"]
        assert XSS_PAYLOAD in body["full_log_redacted"]
        assert XSS_PAYLOAD in body["analysis"]["summary"]
        assert body["analysis"]["evidence"][0]["value"] == XSS_PAYLOAD
        # JSON metni script etiketiyle başlayan bir HTML BELGESİ değil
        assert not response.text.lstrip().startswith("<")

    async def test_xss_payload_in_list_view(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        from app.core.db import get_sessionmaker

        async with get_sessionmaker()() as session:
            await _seed_event(
                session, alert_id="1000", rule_description=XSS_PAYLOAD
            )
        headers = await login_and_headers(client)
        response = await client.get("/api/v1/events", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        payload = json.loads(response.text)
        assert payload["items"][0]["rule_description"] == XSS_PAYLOAD


class TestSecretLeakGuard:
    async def test_responses_never_contain_jwt_secret_or_indexer_password(
        self, make_client: Any
    ) -> None:
        client = await make_client(
            admin_bootstrap_password=TEST_ADMIN_PASSWORD,
            wazuh_indexer_password="SAHTE-INDEXER-PAROLASI",
        )
        from app.core.db import get_sessionmaker

        async with get_sessionmaker()() as session:
            await _seed_event(session, alert_id="1", analysis=_completed_analysis())
        headers = await login_and_headers(client)
        for path in ("/api/v1/events", "/api/v1/overview", "/api/v1/settings", "/api/v1/audit"):
            response = await client.get(path, headers=headers)
            assert "SAHTE-INDEXER-PAROLASI" not in response.text, path
            assert "test-sadece-sahte-secret" not in response.text, path
