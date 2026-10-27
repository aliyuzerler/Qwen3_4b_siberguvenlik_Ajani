"""Refresh token akışı + rate limit API testleri (Faz 05)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy import select

from app.core.db import get_sessionmaker
from app.models.audit import AuditLog
from tests.conftest import TEST_ADMIN_PASSWORD, login_and_headers

pytestmark = pytest.mark.asyncio


class TestRefreshFlow:
    async def test_refresh_returns_new_pair(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        login = (
            await client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": TEST_ADMIN_PASSWORD},
            )
        ).json()
        response = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": login["refresh_token"]}
        )
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["access_token"] and body["refresh_token"]

    async def test_refresh_token_cannot_call_api(self, make_client: Any) -> None:
        """Refresh token'la API çağrısı 401 (tip ayrımı uçtan uca)."""
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        login = (
            await client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": TEST_ADMIN_PASSWORD},
            )
        ).json()
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {login['refresh_token']}"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_refresh_with_access_token_rejected(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        login = (
            await client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": TEST_ADMIN_PASSWORD},
            )
        ).json()
        response = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": login["access_token"]}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_refresh_with_garbage_rejected(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        response = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": "x" * 32}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_refresh_writes_audit(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        login = (
            await client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": TEST_ADMIN_PASSWORD},
            )
        ).json()
        await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": login["refresh_token"]}
        )
        async with get_sessionmaker()() as session:
            actions = {
                row.action for row in (await session.scalars(select(AuditLog))).all()
            }
        assert "auth.refresh.success" in actions


class TestLoginRateLimit:
    async def test_login_blocked_after_limit_with_retry_after(self, make_client: Any) -> None:
        client = await make_client(
            admin_bootstrap_password=TEST_ADMIN_PASSWORD,
            auth_rate_limit_per_minute=3,
        )
        payload = {"username": "admin", "password": "yanlış-parola"}
        statuses: list[int] = []
        for _ in range(5):
            response = await client.post("/api/v1/auth/login", json=payload)
            statuses.append(response.status_code)
        assert statuses[:3] == [401, 401, 401]  # ilk üç deneme doğrulanır
        assert statuses[3] == 429  # fren devrede
        assert statuses[4] == 429
        rate_response = await client.post("/api/v1/auth/login", json=payload)
        assert "retry-after" in rate_response.headers  # httpx başlıkları case-insensitive
        assert int(rate_response.headers["retry-after"]) >= 1
        assert "Çok fazla deneme" in rate_response.json()["detail"]

    async def test_refresh_rate_limited(self, make_client: Any) -> None:
        client = await make_client(
            admin_bootstrap_password=TEST_ADMIN_PASSWORD,
            auth_rate_limit_per_minute=2,
        )
        for _ in range(3):
            response = await client.post(
                "/api/v1/auth/refresh", json={"refresh_token": "x" * 40}
            )
        assert response.status_code == 429

    async def test_rate_limit_does_not_block_other_endpoints(
        self, make_client: Any
    ) -> None:
        """Fren yalnızca auth uçlarında; /health etkilenmez."""
        client = await make_client(
            admin_bootstrap_password=TEST_ADMIN_PASSWORD,
            auth_rate_limit_per_minute=1,
        )
        for _ in range(4):
            health = await client.get("/api/v1/health")
            assert health.status_code == 200


class TestUnauthorizedAccess:
    async def test_protected_endpoints_require_token(self, client: AsyncClient) -> None:
        for path in (
            "/api/v1/events",
            "/api/v1/overview",
            "/api/v1/agents",
            "/api/v1/audit",
            "/api/v1/settings",
        ):
            response = await client.get(path)
            assert response.status_code == status.HTTP_401_UNAUTHORIZED, path
            assert "WWW-Authenticate" in response.headers

    async def test_bogus_token_rejected(self, client: AsyncClient) -> None:
        response = await client.get(
            "/api/v1/events", headers={"Authorization": "Bearer fake.token.parts"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_headers_helper_roundtrip(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        headers = await login_and_headers(client)
        response = await client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == status.HTTP_200_OK
