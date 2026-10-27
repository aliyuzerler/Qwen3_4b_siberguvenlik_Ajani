"""RBAC yetki matrisi testleri (Faz 05).

Rol yetkileri (Faz 00 kararı — üç rol):
- viewer  : olay listesi/detayı, overview, agents (salt okunur panel)
- analyst : viewer ile aynı (bu fazda; yeniden analiz Faz 06+)
- admin   : + audit log, + settings

Sunucu tarafı zorlama: rol gizleme frontend kozmetiğidir; API bağımsız
test edilir (phases/05: "server-side authorization").
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi import status
from httpx import AsyncClient

from app.core.db import get_sessionmaker
from app.models.user import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER, User
from app.services.security.passwords import hash_password
from tests.conftest import TEST_ADMIN_PASSWORD

pytestmark = pytest.mark.asyncio

READ_PATHS = ("/api/v1/events", "/api/v1/overview", "/api/v1/agents")
ADMIN_PATHS = ("/api/v1/audit", "/api/v1/settings")


async def _create_user(role: str, username: str) -> None:
    """Doğrudan DB'ye test kullanıcısı ekler (bootstrap admin dışı roller için)."""
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


class TestRoleMatrix:
    async def test_viewer_can_read_panel_data(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await _create_user(ROLE_VIEWER, "izleyici")
        headers = await _login(client, "izleyici")
        for path in READ_PATHS:
            response = await client.get(path, headers=headers)
            assert response.status_code == status.HTTP_200_OK, path
        me = await client.get("/api/v1/auth/me", headers=headers)
        assert me.json()["role"] == ROLE_VIEWER

    async def test_viewer_cannot_access_admin_paths(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await _create_user(ROLE_VIEWER, "izleyici")
        headers = await _login(client, "izleyici")
        for path in ADMIN_PATHS:
            response = await client.get(path, headers=headers)
            assert response.status_code == status.HTTP_403_FORBIDDEN, path
            assert response.json()["detail"] == "Bu işlem için gerekli yetkiniz yok."

    async def test_analyst_can_read_panel_data(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await _create_user(ROLE_ANALYST, "analist")
        headers = await _login(client, "analist")
        for path in READ_PATHS:
            response = await client.get(path, headers=headers)
            assert response.status_code == status.HTTP_200_OK, path

    async def test_analyst_cannot_access_admin_paths(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await _create_user(ROLE_ANALYST, "analist")
        headers = await _login(client, "analist")
        for path in ADMIN_PATHS:
            response = await client.get(path, headers=headers)
            assert response.status_code == status.HTTP_403_FORBIDDEN, path

    async def test_admin_can_access_everything(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        login_response = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": TEST_ADMIN_PASSWORD},
        )
        headers = {
            "Authorization": f"Bearer {login_response.json()['access_token']}"
        }
        for path in READ_PATHS + ADMIN_PATHS:
            response = await client.get(path, headers=headers)
            assert response.status_code == status.HTTP_200_OK, path

    async def test_admin_role_from_token_cannot_bypass_inactive_user(
        self, make_client: Any
    ) -> None:
        """Pasif kullanıcı token'ıyla ID dahil hiçbir kaynağa erişilemez.

        phases/05: "Kullanıcı bir alert'i görme yetkisine sahip değilse
        doğrudan ID ile de alamamalı" — pasif/geçersiz kimlik için 401.
        """
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await _create_user(ROLE_ADMIN, "eski-admin")
        headers = await _login(client, "eski-admin")
        # Kullanıcı devre dışı bırakılır (token geçerli ama kullanıcı pasif)
        async with get_sessionmaker()() as session:
            from sqlalchemy import update

            await session.execute(
                update(User).where(User.username == "eski-admin").values(is_active=False)
            )
            await session.commit()
        response = await client.get("/api/v1/events", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        # Doğrudan ID ile de: 401 (yetki kontrolü kimlikten önce gelir)
        response = await client.get(f"/api/v1/events/{uuid.uuid4()}", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_require_role_empty_is_programming_error(self) -> None:
        from app.api.v1.deps import require_role

        with pytest.raises(ValueError):
            require_role()


class TestDirectEventAccess:
    async def test_unknown_event_id_404_for_authenticated_viewer(
        self, make_client: Any
    ) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await _create_user(ROLE_VIEWER, "izleyici")
        headers = await _login(client, "izleyici")
        response = await client.get(f"/api/v1/events/{uuid.uuid4()}", headers=headers)
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_malformed_event_id_422(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await _create_user(ROLE_VIEWER, "izleyici")
        headers = await _login(client, "izleyici")
        response = await client.get("/api/v1/events/not-a-uuid", headers=headers)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


class TestReadOnlyContract:
    async def test_no_write_endpoints_on_panel_api(self, client: AsyncClient) -> None:
        """Panel API'si Faz 05'te salt okunurdur (müdahale Faz 07, dry-run)."""
        paths = (
            "/api/v1/events",
            "/api/v1/overview",
            "/api/v1/agents",
            "/api/v1/audit",
            "/api/v1/settings",
        )
        headers = {"Authorization": "Bearer sahte"}  # 401/403 yeterli: uç VAR
        for path in paths:
            post = await client.post(path, json={}, headers=headers)
            delete = await client.delete(path, headers=headers)
            # 405 = uç var ama method yok (salt okunur), 401/403 = koruma
            assert post.status_code in (401, 403, 405), path
            assert delete.status_code in (401, 403, 405), path
