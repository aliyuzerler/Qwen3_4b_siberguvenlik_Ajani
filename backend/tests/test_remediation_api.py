"""Müdahale API testleri (Faz 07).

Kapsam (phases/07 test promptu): "modelden gelen serbest komut, bilinmeyen
action type, yanlış hedef, eksik onay, süresi dolmuş onay, tekrar oynatılan
istek, rate limit, kill switch, audit DB hatası ve executor timeout".

GÜVENCE: tüm yürütmeler FakeRemediationExecutor (conftest) üzerinden
KOŞAR — test sürecinde hiçbir gerçek sistem değişikliği yapılamaz.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy import text

from app.core.db import get_sessionmaker
from tests.conftest import (
    TEST_ADMIN_PASSWORD,
    FakeRemediationExecutor,
    login_and_headers,
    login_headers_for,
)

pytestmark = pytest.mark.asyncio

IDEMPOTENCY_KEY = "test-idem-0001"
EXECUTION_KEY = "test-exec-0001"


# --- Yardımcılar --------------------------------------------------------------


async def _make_rclient(make_client: Any, **overrides: object) -> tuple[AsyncClient, Any]:
    """Müdahale test istemcisi: katalog senkronlu + (client, app) erişimli."""
    from app.services.remediation import sync_remediation_catalog

    client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD, **overrides)
    await sync_remediation_catalog(get_sessionmaker())
    app = client._transport.app  # noqa: SLF001 — test altyapısı
    return client, app


async def _seed_user(
    sessionmaker: Any,
    *,
    username: str,
    role: str,
    password: str = "test-ikinci-parola-123",  # noqa: S107 — SAHTE test değeri
) -> None:
    """İkinci kullanıcı (görev ayrımı testleri) — DB seviyesinde seed."""
    from app.models.user import User
    from app.services.security.passwords import hash_password

    async with sessionmaker() as session:
        session.add(
            User(
                username=username,
                password_hash=hash_password(password),
                role=role,
                is_active=True,
            )
        )
        await session.commit()


async def _seed_events(sessionmaker: Any, *, count: int = 2) -> list[str]:
    """Sentetik kanıt olayları (RFC 5737 doküman IP'leri)."""
    from app.models.event import Event as EventModel

    ids: list[str] = []
    now = datetime.now(UTC)
    async with sessionmaker() as session:
        for index in range(count):
            event = EventModel(
                source="wazuh",
                alert_id=f"100.{index}",
                idempotency_key=f"rem-test:{index}",
                timestamp=now - timedelta(minutes=index),
                received_at=now,
                rule_id="5712",
                rule_level=10,
                rule_description="sshd: Brute force (sentetik)",
                rule_groups=["syslog", "sshd"],
                agent_id="001",
                agent_name="web-server-01",
                manager="wazuh-manager",
                location="/var/log/auth.log",
                src_ip="203.0.113.7",
                fingerprint=f"rem-fp-{index}",
            )
            session.add(event)
            await session.flush()
            ids.append(str(event.id))
        await session.commit()
    return ids


async def _create_proposal(
    client: AsyncClient,
    headers: dict[str, str],
    event_ids: list[str],
    *,
    action_type: str = "notify_admin",
    params: dict[str, Any] | None = None,
    idempotency_key: str = IDEMPOTENCY_KEY,
    correlation_id: str | None = None,
) -> Any:
    return await client.post(
        "/api/v1/remediation/actions",
        headers=headers,
        json={
            "action_type": action_type,
            "params": params or {},
            "event_ids": event_ids,
            "correlation_id": correlation_id,
            "justification": "Sentetik senaryo: brute force doğrulaması sonrası.",
            "idempotency_key": idempotency_key,
        },
    )


async def _approve(
    client: AsyncClient, headers: dict[str, str], action_id: str
) -> Any:
    return await client.post(
        f"/api/v1/remediation/actions/{action_id}/approve",
        headers=headers,
        json={},
    )


async def _execute(
    client: AsyncClient,
    headers: dict[str, str],
    action_id: str,
    execution_key: str = EXECUTION_KEY,
) -> Any:
    return await client.post(
        f"/api/v1/remediation/actions/{action_id}/execute",
        headers=headers,
        json={"execution_key": execution_key},
    )


async def _audit_count(
    sessionmaker: Any, action_name: str
) -> int:
    async with sessionmaker() as session:
        rows = (
            await session.execute(
                text("SELECT COUNT(*) FROM audit_log WHERE action = :a"),
                {"a": action_name},
            )
        ).scalar()
        return int(rows or 0)


# --- RBAC ---------------------------------------------------------------------


class TestRBAC:
    async def test_endpoints_require_authentication(self, make_client: Any) -> None:
        client, _app = await _make_rclient(make_client)
        check = await client.get("/api/v1/remediation/actions")
        assert check.status_code == status.HTTP_401_UNAUTHORIZED
        check = await client.get("/api/v1/remediation/catalog")
        assert check.status_code == status.HTTP_401_UNAUTHORIZED
        check = await client.post(
            "/api/v1/remediation/actions",
            json={"action_type": "notify_admin", "event_ids": [str(uuid.uuid4())],
                  "justification": "yetkisiz deneme", "idempotency_key": "x1"},
        )
        assert check.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_viewer_can_read_but_not_propose(self, make_client: Any) -> None:
        client, app = await _make_rclient(make_client)
        await _seed_user(get_sessionmaker(), username="viewerx", role="viewer")
        viewer_headers = await login_headers_for(
            client, username="viewerx", password="test-ikinci-parola-123"
        )
        check = await client.get("/api/v1/remediation/actions", headers=viewer_headers)
        assert check.status_code == status.HTTP_200_OK
        check = await client.get("/api/v1/remediation/catalog", headers=viewer_headers)
        assert check.status_code == status.HTTP_200_OK
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        check = await _create_proposal(client, viewer_headers, event_ids)
        assert check.status_code == status.HTTP_403_FORBIDDEN

    async def test_analyst_can_propose_but_not_approve_or_execute(
        self, make_client: Any
    ) -> None:
        client, app = await _make_rclient(make_client, policy_mode="dry_run")
        await _seed_user(get_sessionmaker(), username="analystx", role="analyst")
        analyst_headers = await login_headers_for(
            client, username="analystx", password="test-ikinci-parola-123"
        )
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        created = await _create_proposal(client, analyst_headers, event_ids)
        assert created.status_code == status.HTTP_201_CREATED
        action_id = created.json()["action"]["id"]
        admin_headers = await login_and_headers(client)
        check = await _approve(client, analyst_headers, action_id)
        assert check.status_code == status.HTTP_403_FORBIDDEN
        check = await _execute(client, analyst_headers, action_id)
        assert check.status_code == status.HTTP_403_FORBIDDEN
        # admin onayladıktan sonra bile analyst yürütemez
        await _approve(client, admin_headers, action_id)
        check = await _execute(client, analyst_headers, action_id)
        assert check.status_code == status.HTTP_403_FORBIDDEN
        _ = app  # kullanıldı

    async def test_analyst_cannot_toggle_catalog(self, make_client: Any) -> None:
        client, app = await _make_rclient(make_client)
        await _seed_user(get_sessionmaker(), username="analysty", role="analyst")
        analyst_headers = await login_headers_for(
            client, username="analysty", password="test-ikinci-parola-123"
        )
        check = await client.patch(
            "/api/v1/remediation/catalog/restart_wazuh_agent",
            headers=analyst_headers,
            json={"enabled": False},
        )
        assert check.status_code == status.HTTP_403_FORBIDDEN


# --- Öneri oluşturma redleri (politika) -----------------------------------------


class TestCreateProposalRejections:
    async def test_unknown_action_type_rejected_and_audited(
        self, make_client: Any
    ) -> None:
        client, app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        check = await _create_proposal(
            client, headers, event_ids, action_type="run_shell_command"
        )
        assert check.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
        assert check.json()["detail"]["code"] == "unknown_action_type"
        assert await _audit_count(
            get_sessionmaker(), "remediation.action.blocked"
        ) == 1

    async def test_free_form_command_rejected(self, make_client: Any) -> None:
        """Modelden gelse bile serbest komut alanı KABUL EDİLMEZ."""
        client, app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        check = await _create_proposal(
            client,
            headers,
            event_ids,
            action_type="restart_wazuh_agent",
            params={"agent_id": "001", "command": "cat /etc/shadow"},
        )
        assert check.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
        assert check.json()["detail"]["code"] == "invalid_params"

    async def test_wrong_target_rejected(self, make_client: Any) -> None:
        """'yanlış hedef': agent_id kanıt olaylarında yok → 422 target_scope."""
        client, app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        check = await _create_proposal(
            client,
            headers,
            event_ids,
            action_type="restart_wazuh_agent",
            params={"agent_id": "999"},
        )
        assert check.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
        assert check.json()["detail"]["code"] == "target_scope"

    async def test_nonexistent_event_rejected(self, make_client: Any) -> None:
        client, app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        check = await _create_proposal(
            client, headers, [str(uuid.uuid4())]
        )
        assert check.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
        assert check.json()["detail"]["code"] == "target_not_found"

    async def test_firewall_action_blocked_by_default(self, make_client: Any) -> None:
        """Kritik erişim: firewall aksiyonu varsayılan iki kapıyla da kapalı → RED.

        Motor sırası: action_enabled (DB'de default false) ilk kapıdır;
        admin enabled yapsaydı ikinci kapı (default_blocked) devreye girerdi
        (bkz. policy birim testleri + test_firewall_action_still_blocked...).
        """
        client, app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        check = await _create_proposal(
            client,
            headers,
            event_ids,
            action_type="block_src_ip",
            params={"ip": "203.0.113.7"},
        )
        assert check.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
        assert check.json()["detail"]["code"] in {"action_disabled", "default_blocked"}

    async def test_firewall_action_still_blocked_when_admin_enables_only(
        self, make_client: Any
    ) -> None:
        """İki bağımsız kapı: admin enable yeterli DEĞİL; global flag gerekir."""
        client, app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        check = await client.patch(
            "/api/v1/remediation/catalog/block_src_ip",
            headers=headers,
            json={"enabled": True},
        )
        # Admin enable (kapı 2) isteği default_blocked nedeniyle 409 ile RED.
        assert check.status_code == status.HTTP_409_CONFLICT
        assert check.json()["detail"]["code"] == "default_blocked"

    async def test_firewall_action_passes_with_both_gates_dry_run(
        self, make_client: Any
    ) -> None:
        """Her iki kapı açık + dry_run: yürütme SİMÜLASYON (kural eklenmez)."""
        client, app = await _make_rclient(
            make_client,
            policy_mode="dry_run",
            remediation_allow_blocked_actions=True,
        )
        admin_headers = await login_and_headers(client)
        # admin != öneren: ikinci admin seed et
        await _seed_user(get_sessionmaker(), username="admin2", role="admin")
        admin2_headers = await login_headers_for(
            client, username="admin2", password="test-ikinci-parola-123"
        )
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        # admin2 önerir (kapı 2 admin PATCH'i admin2 ile de olur)
        toggle = await client.patch(
            "/api/v1/remediation/catalog/block_src_ip",
            headers=admin2_headers,
            json={"enabled": True},
        )
        assert toggle.status_code == status.HTTP_200_OK
        created = await _create_proposal(
            client,
            admin2_headers,
            event_ids,
            action_type="block_src_ip",
            params={"ip": "203.0.113.7"},
            idempotency_key="fw-idem-0001",
        )
        assert created.status_code == status.HTTP_201_CREATED
        action_id = created.json()["action"]["id"]
        fake = FakeRemediationExecutor()
        app.state.remediation_executor = fake
        approved = await _approve(client, admin_headers, action_id)
        assert approved.status_code == status.HTTP_200_OK
        executed = await _execute(client, admin_headers, action_id)
        assert executed.status_code == status.HTTP_200_OK
        assert executed.json()["action"]["status"] == "executed"
        assert executed.json()["action"]["execution_result"]["simulated"] is True
        assert len(fake.calls) == 1  # yalnızca fake — gerçek değişiklik YOK

    async def test_disabled_action_rejected(self, make_client: Any) -> None:
        client, app = await _make_rclient(make_client)
        admin_headers = await login_and_headers(client)
        toggle = await client.patch(
            "/api/v1/remediation/catalog/run_antivirus_scan",
            headers=admin_headers,
            json={"enabled": False},
        )
        assert toggle.status_code == status.HTTP_200_OK
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        check = await _create_proposal(
            client,
            admin_headers,
            event_ids,
            action_type="run_antivirus_scan",
            params={"agent_id": "001"},
            idempotency_key="dis-idem-0001",
        )
        assert check.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
        assert check.json()["detail"]["code"] == "action_disabled"

    async def test_kill_switch_blocks_creation(self, make_client: Any) -> None:
        client, app = await _make_rclient(make_client, remediation_enabled=False)
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        check = await _create_proposal(client, headers, event_ids)
        assert check.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert check.json()["detail"]["code"] == "kill_switch"

    async def test_rate_limit_blocks_creation(self, make_client: Any) -> None:
        client, app = await _make_rclient(
            make_client, remediation_rate_limit_per_hour=2
        )
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        for index in range(2):
            ok = await _create_proposal(
                client, headers, event_ids, idempotency_key=f"rl-idem-{index}"
            )
            assert ok.status_code == status.HTTP_201_CREATED
        limited = await _create_proposal(client, headers, event_ids, idempotency_key="rl-idem-9")
        assert limited.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "Retry-After" in limited.headers
        assert await _audit_count(
            get_sessionmaker(), "remediation.action.rate_limited"
        ) == 1


# --- Öneri oluşturma başarıları ---------------------------------------------------


class TestCreateProposalSuccess:
    async def test_create_builds_server_side_evidence(self, make_client: Any) -> None:
        client, app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=2)
        created = await _create_proposal(client, headers, event_ids)
        assert created.status_code == status.HTTP_201_CREATED
        body = created.json()
        assert body["created"] is True
        action = body["action"]
        assert action["status"] == "proposed"
        evidence = action["evidence"]
        assert set(evidence["event_ids"]) == set(event_ids)  # sunucu üretimi
        assert evidence["alert_ids"] == ["100.0", "100.1"]
        assert evidence["agent_ids"] == ["001"]
        assert evidence["src_ips"] == ["203.0.113.7"]
        assert evidence["max_rule_level"] == 10
        assert evidence["risk_explanation"]
        assert evidence["rollback_note"]
        checks = action["policy_decision"]["checks"]
        assert all(c["passed"] for c in checks)
        assert await _audit_count(
            get_sessionmaker(), "remediation.action.proposed"
        ) == 1

    async def test_idempotent_recreate_returns_same_row(self, make_client: Any) -> None:
        client, app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        first = await _create_proposal(client, headers, event_ids)
        assert first.status_code == status.HTTP_201_CREATED
        second = await _create_proposal(client, headers, event_ids)
        assert second.status_code == status.HTTP_200_OK  # 201 DEĞİL
        assert second.json()["created"] is False
        assert second.json()["action"]["id"] == first.json()["action"]["id"]
        # Tekrar oynatılan öneri isteği audit'e yeni 'proposed' yazmaz.
        assert await _audit_count(
            get_sessionmaker(), "remediation.action.proposed"
        ) == 1

    async def test_list_and_detail(self, make_client: Any) -> None:
        client, app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        created = await _create_proposal(client, headers, event_ids)
        action_id = created.json()["action"]["id"]
        listing = await client.get("/api/v1/remediation/actions", headers=headers)
        assert listing.status_code == status.HTTP_200_OK
        assert listing.json()["total"] == 1
        detail = await client.get(
            f"/api/v1/remediation/actions/{action_id}", headers=headers
        )
        assert detail.status_code == status.HTTP_200_OK
        assert detail.json()["evidence"]["event_ids"] == event_ids
        missing = await client.get(
            f"/api/v1/remediation/actions/{uuid.uuid4()}", headers=headers
        )
        assert missing.status_code == status.HTTP_404_NOT_FOUND


# --- Onay / ret (görev ayrımı) -----------------------------------------------------


class TestApprovalFlow:
    async def test_self_approval_denied(self, make_client: Any) -> None:
        client, app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        created = await _create_proposal(client, headers, event_ids)
        action_id = created.json()["action"]["id"]
        check = await _approve(client, headers, action_id)
        assert check.status_code == status.HTTP_409_CONFLICT
        assert check.json()["detail"]["code"] == "self_approval"

    async def test_second_admin_can_approve_and_recorded(self, make_client: Any) -> None:
        client, app = await _make_rclient(make_client, policy_mode="dry_run")
        await _seed_user(get_sessionmaker(), username="admin2", role="admin")
        headers = await login_and_headers(client)
        admin2_headers = await login_headers_for(
            client, username="admin2", password="test-ikinci-parola-123"
        )
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        created = await _create_proposal(client, headers, event_ids)
        action_id = created.json()["action"]["id"]
        approved = await _approve(client, admin2_headers, action_id)
        assert approved.status_code == status.HTTP_200_OK
        body = approved.json()
        assert body["action"]["status"] == "approved"
        assert body["action"]["approved_by_username"] == "admin2"
        assert await _audit_count(
            get_sessionmaker(), "remediation.action.approved"
        ) == 1

    async def test_self_approval_escape_hatch(self, make_client: Any) -> None:
        """REMEDIATION_ALLOW_SELF_APPROVAL=true → tek-admin kurulum bilinçli istisna."""
        client, app = await _make_rclient(
            make_client, policy_mode="dry_run", remediation_allow_self_approval=True
        )
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        created = await _create_proposal(client, headers, event_ids)
        action_id = created.json()["action"]["id"]
        approved = await _approve(client, headers, action_id)
        assert approved.status_code == status.HTTP_200_OK
        _ = app

    async def test_execute_without_approval_denied(self, make_client: Any) -> None:
        """'eksik onay': proposed durumunda yürütme 409 (executor çağrılmaz)."""
        client, app = await _make_rclient(make_client, policy_mode="dry_run")
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        created = await _create_proposal(client, headers, event_ids)
        action_id = created.json()["action"]["id"]
        fake = FakeRemediationExecutor()
        app.state.remediation_executor = fake
        check = await _execute(client, headers, action_id)
        assert check.status_code == status.HTTP_409_CONFLICT
        assert check.json()["detail"]["code"] == "not_approved"
        assert fake.calls == []  # sistem değişikliği YOK

    async def test_expired_approval_blocks_execution(self, make_client: Any) -> None:
        """'süresi dolmuş onay': TTL aşımı → expired + 409."""
        client, app = await _make_rclient(
            make_client, policy_mode="dry_run", remediation_approval_ttl_minutes=30
        )
        await _seed_user(get_sessionmaker(), username="admin2", role="admin")
        headers = await login_and_headers(client)
        admin2_headers = await login_headers_for(
            client, username="admin2", password="test-ikinci-parola-123"
        )
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        created = await _create_proposal(client, headers, event_ids)
        action_id = created.json()["action"]["id"]
        approved = await _approve(client, admin2_headers, action_id)
        assert approved.status_code == status.HTTP_200_OK
        # Onay zamanını geriye çek (TTL 30 dk; 2 saat önce)
        from app.models.remediation import RemediationAction

        async with get_sessionmaker()() as session:
            row = await session.get(RemediationAction, uuid.UUID(action_id))
            assert row is not None
            row.approved_at = datetime.now(UTC) - timedelta(hours=2)
            await session.commit()
        fake = FakeRemediationExecutor()
        app.state.remediation_executor = fake
        check = await _execute(client, headers, action_id)
        assert check.status_code == status.HTTP_409_CONFLICT
        assert check.json()["detail"]["code"] == "approval_expired"
        assert fake.calls == []
        detail = await client.get(
            f"/api/v1/remediation/actions/{action_id}", headers=headers
        )
        assert detail.json()["status"] == "expired"
        assert await _audit_count(
            get_sessionmaker(), "remediation.action.blocked"
        ) == 1

    async def test_reject_flow(self, make_client: Any) -> None:
        client, app = await _make_rclient(make_client)
        await _seed_user(get_sessionmaker(), username="admin2", role="admin")
        headers = await login_and_headers(client)
        admin2_headers = await login_headers_for(
            client, username="admin2", password="test-ikinci-parola-123"
        )
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        created = await _create_proposal(client, headers, event_ids)
        action_id = created.json()["action"]["id"]
        check = await client.post(
            f"/api/v1/remediation/actions/{action_id}/reject",
            headers=admin2_headers,
            json={"reason": "Sentetik ret: ek kanıt gerekiyor."},
        )
        assert check.status_code == status.HTTP_200_OK
        assert check.json()["action"]["status"] == "rejected"
        # rejected durumunda yürütme reddedilir
        exec_check = await _execute(client, admin2_headers, action_id)
        assert exec_check.status_code == status.HTTP_409_CONFLICT
        assert await _audit_count(
            get_sessionmaker(), "remediation.action.rejected"
        ) == 1

    async def test_reject_requires_reason(self, make_client: Any) -> None:
        client, app = await _make_rclient(make_client)
        await _seed_user(get_sessionmaker(), username="admin2", role="admin")
        headers = await login_and_headers(client)
        admin2_headers = await login_headers_for(
            client, username="admin2", password="test-ikinci-parola-123"
        )
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        created = await _create_proposal(client, headers, event_ids)
        action_id = created.json()["action"]["id"]
        check = await client.post(
            f"/api/v1/remediation/actions/{action_id}/reject",
            headers=admin2_headers,
            json={"reason": "abc"},  # 5 karakterin altı → 422
        )
        assert check.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# --- Yürütme akışı (dry-run + replay + timeout + arıza) ---------------------------


async def _prepare_approved(
    client: AsyncClient,
    app: Any,
    *,
    policy_mode: str = "dry_run",
    requester: str = "admin",
) -> str:
    """Onaylı öneri hazırlar (öneren admin; onaylayan admin2)."""
    if requester == "admin":
        await _seed_user(get_sessionmaker(), username="admin2", role="admin")
    requester_headers = (
        await login_headers_for(client, username="admin2", password="test-ikinci-parola-123")
        if requester == "admin2"
        else await login_and_headers(client)
    )
    approver_headers = (
        await login_headers_for(client, username="admin2", password="test-ikinci-parola-123")
        if requester == "admin"
        else await login_and_headers(client)
    )
    event_ids = await _seed_events(get_sessionmaker(), count=1)
    created = await _create_proposal(
        client,
        requester_headers,
        event_ids,
        action_type="restart_wazuh_agent",
        params={"agent_id": "001"},
        idempotency_key=f"prep-{uuid.uuid4().hex[:8]}",
    )
    assert created.status_code == status.HTTP_201_CREATED, created.text
    action_id = created.json()["action"]["id"]
    approved = await _approve(client, approver_headers, action_id)
    assert approved.status_code == status.HTTP_200_OK, approved.text
    _ = policy_mode
    return action_id


class TestExecutionFlow:
    async def test_observe_only_blocks_execution_and_never_calls_executor(
        self, make_client: Any
    ) -> None:
        """observe_only: yürütme 409 + executor HİÇ çağrılmaz (sistem değişikliği YOK)."""
        client, app = await _make_rclient(make_client)  # varsayılan observe_only
        action_id = await _prepare_approved(client, app)
        fake = FakeRemediationExecutor()
        app.state.remediation_executor = fake
        headers = await login_and_headers(client)
        check = await _execute(client, headers, action_id)
        assert check.status_code == status.HTTP_409_CONFLICT
        assert check.json()["detail"]["code"] == "mode_blocked"
        assert fake.calls == []  # EN KRİTİK KANIT: executor'a ULAŞILMADI
        assert await _audit_count(
            get_sessionmaker(), "remediation.action.blocked"
        ) == 1  # mode_blocked audit'li

    async def test_dry_run_execution_records_simulated_result(
        self, make_client: Any
    ) -> None:
        client, app = await _make_rclient(make_client, policy_mode="dry_run")
        action_id = await _prepare_approved(client, app)
        fake = FakeRemediationExecutor()
        app.state.remediation_executor = fake
        headers = await login_and_headers(client)
        executed = await _execute(client, headers, action_id)
        assert executed.status_code == status.HTTP_200_OK
        body = executed.json()
        assert body["action"]["status"] == "executed"
        assert body["action"]["execution_result"]["simulated"] is True
        assert body["replayed"] is False
        assert len(fake.calls) == 1
        assert fake.calls[0]["action_type"] == "restart_wazuh_agent"
        assert await _audit_count(
            get_sessionmaker(), "remediation.action.executed"
        ) == 1

    async def test_replay_same_key_returns_original_without_double_execution(
        self, make_client: Any
    ) -> None:
        """'tekrar oynatılan istek': aynı execution_key → replayed=true, çift yürütme YOK."""
        client, app = await _make_rclient(make_client, policy_mode="dry_run")
        action_id = await _prepare_approved(client, app)
        fake = FakeRemediationExecutor()
        app.state.remediation_executor = fake
        headers = await login_and_headers(client)
        first = await _execute(client, headers, action_id)
        assert first.status_code == status.HTTP_200_OK
        replay = await _execute(client, headers, action_id)
        assert replay.status_code == status.HTTP_200_OK
        assert replay.json()["replayed"] is True
        assert replay.json()["action"]["id"] == action_id
        assert len(fake.calls) == 1  # İKİNCİ executor çağrısı YOK
        assert await _audit_count(
            get_sessionmaker(), "remediation.action.replayed"
        ) == 1

    async def test_replayed_request_with_different_key_is_denied(
        self, make_client: Any
    ) -> None:
        client, app = await _make_rclient(make_client, policy_mode="dry_run")
        action_id = await _prepare_approved(client, app)
        fake = FakeRemediationExecutor()
        app.state.remediation_executor = fake
        headers = await login_and_headers(client)
        first = await _execute(client, headers, action_id)
        assert first.status_code == status.HTTP_200_OK
        second = await _execute(
            client, headers, action_id, execution_key="baska-anahtar-2"
        )
        assert second.status_code == status.HTTP_409_CONFLICT
        assert second.json()["detail"]["code"] == "already_executed"
        assert len(fake.calls) == 1

    async def test_executor_timeout_marks_failed(self, make_client: Any) -> None:
        """'executor timeout': sınır aşımı → status=failed + executor_timeout."""
        client, app = await _make_rclient(
            make_client,
            policy_mode="dry_run",
            remediation_executor_timeout_seconds=0.05,
        )
        action_id = await _prepare_approved(client, app)
        slow = FakeRemediationExecutor(latency_seconds=1.0)
        app.state.remediation_executor = slow
        headers = await login_and_headers(client)
        executed = await _execute(client, headers, action_id)
        assert executed.status_code == status.HTTP_200_OK  # HTTP 200, DURUM failed
        body = executed.json()
        assert body["action"]["status"] == "failed"
        assert body["action"]["execution_error"] is not None
        assert "executor_timeout" in body["action"]["execution_error"]
        assert await _audit_count(
            get_sessionmaker(), "remediation.action.failed"
        ) == 1

    async def test_executor_failure_marks_failed_with_audit(
        self, make_client: Any
    ) -> None:
        client, app = await _make_rclient(make_client, policy_mode="dry_run")
        action_id = await _prepare_approved(client, app)
        failing = FakeRemediationExecutor(fail=True)
        app.state.remediation_executor = fake_fail = failing
        headers = await login_and_headers(client)
        executed = await _execute(client, headers, action_id)
        assert executed.status_code == status.HTTP_200_OK
        assert executed.json()["action"]["status"] == "failed"
        assert "fake_denied" in executed.json()["action"]["execution_error"]
        assert len(fake_fail.calls) == 1
        _ = app

    async def test_execute_rate_limit(self, make_client: Any) -> None:
        """Yürütme ucu da aynı kullanıcı tavanına tabidir (429 + Retry-After).

        Tavan sayacı yalnızca create+execute uçlarını sayar (approve sayılmaz):
        limit=2 → create(1) + execute(2) → sonraki execute 429.
        """
        client, app = await _make_rclient(
            make_client, policy_mode="dry_run", remediation_rate_limit_per_hour=2
        )
        action_id = await _prepare_approved(client, app)
        app.state.remediation_executor = FakeRemediationExecutor()
        headers = await login_and_headers(client)
        ok = await _execute(client, headers, action_id)
        assert ok.status_code == status.HTTP_200_OK
        # Tavan doldu: yeni yürütme denemesi 429 (geçersiz id bile — fren önce)
        check = await client.post(
            f"/api/v1/remediation/actions/{uuid.uuid4()}/execute",
            headers=headers,
            json={"execution_key": "rate-limit-key-1"},
        )
        assert check.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "Retry-After" in check.headers


class TestAuditDBFailure:
    async def test_flow_survives_audit_db_failure(self, make_client: Any) -> None:
        """'audit DB hatası': audit_log tablosu KIRIKken akış tamamlanır.

        AuditService sözleşmesi: audit yazımı başarısız olsa bile akış
        bozulmaz (audit kilitlenme vektörü olamaz); hata loglanır. Kalıcı
        iz, remediation_actions satırındaki durum geçişinde yaşar.
        """
        client, app = await _make_rclient(make_client, policy_mode="dry_run")
        action_id = await _prepare_approved(client, app)
        # audit_log tablosunu DÜŞÜR (gerçek DB arızası simülasyonu)
        engine = app.state.engine
        async with engine.begin() as connection:
            await connection.execute(text("DROP TABLE audit_log"))
        app.state.remediation_executor = FakeRemediationExecutor()
        headers = await login_and_headers(client)
        executed = await _execute(client, headers, action_id)
        # Audit yazımı başarısız → AKIŞ DEVAM EDER (yürütme tamamlanır).
        assert executed.status_code == status.HTTP_200_OK
        assert executed.json()["action"]["status"] == "executed"
        # Durum makinesi kaydı audit_log'dan bağımsız yaşar:
        detail = await client.get(
            f"/api/v1/remediation/actions/{action_id}", headers=headers
        )
        assert detail.json()["execution_count"] == 1


class TestCatalogEndpoint:
    async def test_catalog_lists_six_actions_with_gates(self, make_client: Any) -> None:
        client, _app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        check = await client.get("/api/v1/remediation/catalog", headers=headers)
        assert check.status_code == status.HTTP_200_OK
        body = check.json()
        assert len(body["items"]) == 6
        assert body["policy_mode"] == "observe_only"
        assert body["remediation_enabled"] is True
        assert body["allow_blocked_actions"] is False
        by_key = {item["action_type"]: item for item in body["items"]}
        assert by_key["notify_admin"]["enabled"] is True
        assert by_key["block_src_ip"]["default_blocked"] is True
        assert by_key["block_src_ip"]["enabled"] is False  # iki kapı ilkesi
        assert by_key["restart_wazuh_agent"]["rollback_note"]

    async def test_admin_toggle_updated_and_unchanged(self, make_client: Any) -> None:
        client, _app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        first = await client.patch(
            "/api/v1/remediation/catalog/run_antivirus_scan",
            headers=headers,
            json={"enabled": False},
        )
        assert first.status_code == status.HTTP_200_OK
        assert first.json()["result"] == "updated"
        assert first.json()["enabled"] is False
        second = await client.patch(
            "/api/v1/remediation/catalog/run_antivirus_scan",
            headers=headers,
            json={"enabled": False},
        )
        assert second.json()["result"] == "unchanged"
        unknown = await client.patch(
            "/api/v1/remediation/catalog/bilinmeyen_tip",
            headers=headers,
            json={"enabled": True},
        )
        assert unknown.status_code == status.HTTP_404_NOT_FOUND

    async def test_blocked_action_toggle_requires_global_flag(
        self, make_client: Any
    ) -> None:
        client, _app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        denied = await client.patch(
            "/api/v1/remediation/catalog/isolate_host",
            headers=headers,
            json={"enabled": True},
        )
        assert denied.status_code == status.HTTP_409_CONFLICT
        assert denied.json()["detail"]["code"] == "default_blocked"
        # Global kapı açıkken admin enable edebilir
        client2, _app2 = await _make_rclient(
            make_client, remediation_allow_blocked_actions=True
        )
        headers2 = await login_and_headers(client2)
        allowed = await client2.patch(
            "/api/v1/remediation/catalog/isolate_host",
            headers=headers2,
            json={"enabled": True},
        )
        assert allowed.status_code == status.HTTP_200_OK
        assert allowed.json()["enabled"] is True


class TestConcurrentCreateRace:
    async def test_unique_race_falls_back_to_existing_row(
        self, make_client: Any, monkeypatch: Any
    ) -> None:
        """Bulgu F3 kapanma testi: eşzamanlı aynı idempotency_key yarışında
        UNIQUE çakışması (IntegrityError) → 500 DEĞİL, mevcut satır döner."""
        from sqlalchemy.exc import IntegrityError

        from app.services.remediation.service import create_proposal

        client, app = await _make_rclient(make_client)
        headers = await login_and_headers(client)
        event_ids = await _seed_events(get_sessionmaker(), count=1)
        # Önce normal akışla öneri oluştur (yarışı kazanan yazar).
        created = await _create_proposal(client, headers, event_ids)
        assert created.status_code == status.HTTP_201_CREATED
        winning_id = created.json()["action"]["id"]
        settings = app.state.settings
        current_user_id = "00000000-0000-0000-0000-000000000001"

        # Yarışı KAYBEDEN yazar: commit'i IntegrityError ile düşür (UNIQUE
        # çakışması simülasyonu) → servis idempotent yola düşmeli.
        async with get_sessionmaker()() as session:
            original_commit = session.commit
            state = {"first": True}

            async def racing_commit() -> None:
                if state["first"]:
                    state["first"] = False
                    raise IntegrityError(
                        "simulated UNIQUE race", None, Exception("UNIQUE constraint failed")
                    )
                await original_commit()

            monkeypatch.setattr(session, "commit", racing_commit)
            action_id, created_flag = await create_proposal(
                session,
                settings=settings,
                requested_by_user_id=current_user_id,
                requested_by_username="race-loser",
                action_type="notify_admin",
                params={},
                event_ids=event_ids,
                correlation_id=None,
                justification="Yarışı kaybeden eşzamanlı istek (test).",
                idempotency_key="test-idem-0001",  # kazananla AYNI
            )
            assert created_flag is False
            assert str(action_id) == winning_id  # AYNI satır (yeni satır yok)
