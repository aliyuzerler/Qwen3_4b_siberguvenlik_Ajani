"""Kullanıcı yönetimi API testleri (Faz 08).

Kapsam (phases/08: "RBAC ve audit" + kullanıcı yönetimi):
- RBAC: /users uçları yalnızca admin (viewer/analyst 403; anonim 401).
- POST /users: 201 + şema (parola hash'i YOK); zayıf parola 422; tekrar
  kullanıcı adı 409; büyük/küçük harf normalize; bozuk kullanıcı adı 422.
- PATCH /users/{id}: rol + aktiflik; self-disable 409; son-aktif-admin 409;
  devre dışı bırakılan kullanıcının token'ı anında değersizleşir (401).
- POST /users/me/password: yanlış önbilgi 400; doğrulu → yeni parola ile
  giriş; zayıf parola 422; tüm roller erişebilir (viewer dahil).
- POST /users/{id}/password (admin): self-sıfırlama 409; başkası için
  çalışır; zayıf parola 422.
- Audit: user.created / user.updated / user.password_changed /
  user.password_reset kayıtları; parola değeri asla kayıtlarda YOK.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import app.models  # noqa: F401
from app.core.db import Base, dispose_engine, get_sessionmaker
from app.main import create_app
from app.models.audit import AuditLog
from app.services.security import bootstrap_admin_if_empty
from tests.conftest import TEST_ADMIN_PASSWORD, login_headers_for, make_settings

TEST_USER_PASSWORD = "guclu-test-parolasi-123"  # noqa: S105  # yalnızca test değeri


@pytest.fixture
async def make_fresh_client(tmp_path: Any) -> AsyncIterator[Any]:
    """Kullanıcı testleri için izole istemci fabrikası (conftest.make_client ile aynı sözleşme)."""
    clients: list[AsyncClient] = []

    async def _make(**overrides: object) -> AsyncClient:
        application = create_app(make_settings(tmp_path, **overrides))
        async with application.state.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        transport = ASGITransport(app=application)
        http_client = AsyncClient(transport=transport, base_url="http://testserver")
        from app.services.security.audit import AuditAction, AuditService

        async with get_sessionmaker()() as bootstrap_session:
            created = await bootstrap_admin_if_empty(
                bootstrap_session,
                username=application.state.settings.admin_bootstrap_username,
                password=application.state.settings.admin_bootstrap_password,
            )
            if created:
                await AuditService(bootstrap_session).record(
                    action=AuditAction.BOOTSTRAP_ADMIN_CREATED,
                    actor=application.state.settings.admin_bootstrap_username,
                    detail={"mechanism": "startup_bootstrap"},
                )
        clients.append(http_client)
        return http_client

    yield _make
    for http_client in clients:
        await http_client.aclose()
    await dispose_engine()


async def create_user(
    client: AsyncClient,
    admin_headers: dict[str, str],
    *,
    username: str,
    password: str = TEST_USER_PASSWORD,
    role: str = "viewer",
) -> dict[str, Any]:
    response = await client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"username": username, "password": password, "role": role},
    )
    assert response.status_code == 201, response.text
    return response.json()["user"]


async def audit_actions(session: AsyncSession) -> list[str]:
    rows = (await session.scalars(select(AuditLog.action).order_by(AuditLog.created_at))).all()
    return [str(action) for action in rows]


async def actions_via_global_sessionmaker() -> list[str]:
    """Global engine üzerinden audit aksiyonları (create_app init_engine kullandı)."""
    async with get_sessionmaker()() as session:
        return await audit_actions(session)


class TestUsersRbac:
    async def test_anonymous_cannot_list_users(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        response = await client.get("/api/v1/users")
        assert response.status_code == 401

    async def test_viewer_and_analyst_forbidden(
        self, make_fresh_client, tmp_path: Any
    ) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        for role in ("viewer", "analyst"):
            body = {
                "username": f"user-{role}",
                "password": TEST_USER_PASSWORD,
                "role": role,
            }
            response = await client.post("/api/v1/users", headers=admin_headers, json=body)
            assert response.status_code == 201
            role_headers = await login_headers_for(
                client, username=f"user-{role}", password=TEST_USER_PASSWORD
            )
            for method, path in (
                ("GET", "/api/v1/users"),
                ("POST", "/api/v1/users"),
                ("PATCH", "/api/v1/users/00000000-0000-0000-0000-000000000000"),
                ("POST", "/api/v1/users/00000000-0000-0000-0000-000000000000/password"),
            ):
                if method == "GET":
                    r = await client.get(path, headers=role_headers)
                elif method == "POST":
                    r = await client.post(path, headers=role_headers, json={})
                else:
                    r = await client.patch(path, headers=role_headers, json={})
                assert r.status_code == 403, f"{role} {method} {path} → {r.status_code}"

    async def test_admin_can_list_users(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        response = await client.get("/api/v1/users", headers=admin_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 1
        assert body["items"][0]["username"] == "admin"
        assert "password" not in body["items"][0]
        assert "password_hash" not in body["items"][0]


class TestCreateUser:
    async def test_create_user_201_without_hash_leak(
        self, make_fresh_client
    ) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        user = await create_user(
            client, admin_headers, username="analyst-one", role="analyst"
        )
        assert user["username"] == "analyst-one"
        assert user["role"] == "analyst"
        assert user["is_active"] is True
        assert "password_hash" not in user

    async def test_created_user_can_login(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        await create_user(client, admin_headers, username="viewer-two")
        response = await client.post(
            "/api/v1/auth/login",
            json={"username": "viewer-two", "password": TEST_USER_PASSWORD},
        )
        assert response.status_code == 200

    async def test_username_normalized_lowercase(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        response = await client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "username": "  MixedCase-User ",
                "password": TEST_USER_PASSWORD,
                "role": "viewer",
            },
        )
        assert response.status_code == 201
        assert response.json()["user"]["username"] == "mixedcase-user"

    async def test_duplicate_username_409(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        response = await client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={"username": "admin", "password": TEST_USER_PASSWORD, "role": "viewer"},
        )
        assert response.status_code == 409
        assert response.json()["code"] == "username_taken"

    async def test_weak_password_422(self, make_fresh_client) -> None:
        client = await make_fresh_client(user_password_min_length=12)
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        response = await client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={"username": "weakpw", "password": "kisa-123", "role": "viewer"},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "weak_password"

    async def test_bad_username_shape_422(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        for bad in ("ab", "boşluklu kullanıcı", "-baslik", "cok-uzun-" + "x" * 70):
            response = await client.post(
                "/api/v1/users",
                headers=admin_headers,
                json={"username": bad, "password": TEST_USER_PASSWORD, "role": "viewer"},
            )
            assert response.status_code == 422, f"{bad!r} reddedilmeli"

    async def test_invalid_role_422(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        response = await client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={"username": "boyle-bir-rol", "password": TEST_USER_PASSWORD, "role": "root"},
        )
        assert response.status_code == 422

    async def test_create_user_audited(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        await create_user(client, admin_headers, username="audit-target")
        actions = await actions_via_global_sessionmaker()
        assert "user.created" in actions
        # Parola değeri asla audit detayında yok (yapısal tarama)
        assert TEST_USER_PASSWORD not in actions


class TestUpdateUser:
    async def test_role_change_effective_immediately(self, make_fresh_client) -> None:
        """Rol değişimi: DB'den okunan güncel rol yetkiyi ANINDA değiştirir."""
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        user = await create_user(client, admin_headers, username="promoted")
        viewer_headers = await login_headers_for(
            client, username="promoted", password=TEST_USER_PASSWORD
        )
        # Viewer: audit listesi 403
        response = await client.get("/api/v1/audit", headers=viewer_headers)
        assert response.status_code == 403
        # Admin promte eder
        response = await client.patch(
            f"/api/v1/users/{user['id']}", headers=admin_headers, json={"role": "admin"}
        )
        assert response.status_code == 200
        assert response.json()["user"]["role"] == "admin"
        # AYNI token ile audit listesi artık 200 (yetki DB'den gelir)
        response = await client.get("/api/v1/audit", headers=viewer_headers)
        assert response.status_code == 200

    async def test_cannot_disable_self(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        # admin'in kendi id'si
        me = await client.get("/api/v1/auth/me", headers=admin_headers)
        admin_id = me.json()["id"]
        response = await client.patch(
            f"/api/v1/users/{admin_id}", headers=admin_headers, json={"is_active": False}
        )
        assert response.status_code == 409
        assert response.json()["code"] == "cannot_disable_self"

    async def test_last_active_admin_cannot_be_demoted_or_disabled(
        self, make_fresh_client
    ) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        user = await create_user(client, admin_headers, username="other-admin", role="admin")
        # İki admin varken "other-admin" kapatılabilir
        response = await client.patch(
            f"/api/v1/users/{user['id']}", headers=admin_headers, json={"is_active": False}
        )
        assert response.status_code == 200
        # Şimdi tek admin kaldı: demote 409
        me = await client.get("/api/v1/auth/me", headers=admin_headers)
        admin_id = me.json()["id"]
        response = await client.patch(
            f"/api/v1/users/{admin_id}", headers=admin_headers, json={"role": "viewer"}
        )
        assert response.status_code == 409
        assert response.json()["code"] == "last_active_admin"

    async def test_disabled_user_token_immediately_invalid(
        self, make_fresh_client
    ) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        user = await create_user(client, admin_headers, username="suspend-me")
        user_headers = await login_headers_for(
            client, username="suspend-me", password=TEST_USER_PASSWORD
        )
        assert (await client.get("/api/v1/auth/me", headers=user_headers)).status_code == 200
        # Devre dışı bırak
        response = await client.patch(
            f"/api/v1/users/{user['id']}", headers=admin_headers, json={"is_active": False}
        )
        assert response.status_code == 200
        # Eski access token ANINDA geçersiz (DB aktiflik kontrolü)
        assert (await client.get("/api/v1/auth/me", headers=user_headers)).status_code == 401
        # Login da artık 401 (is_active=false)
        relogin = await client.post(
            "/api/v1/auth/login",
            json={"username": "suspend-me", "password": TEST_USER_PASSWORD},
        )
        assert relogin.status_code == 401

    async def test_unknown_user_404(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        response = await client.patch(
            "/api/v1/users/00000000-0000-0000-0000-000000000000",
            headers=admin_headers,
            json={"role": "viewer"},
        )
        assert response.status_code == 404

    async def test_no_changes_422(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        user = await create_user(client, admin_headers, username="noop-user")
        response = await client.patch(
            f"/api/v1/users/{user['id']}", headers=admin_headers, json={}
        )
        assert response.status_code == 422

    async def test_update_user_audited(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        user = await create_user(client, admin_headers, username="audited-user")
        await client.patch(
            f"/api/v1/users/{user['id']}", headers=admin_headers, json={"role": "analyst"}
        )
        actions = await actions_via_global_sessionmaker()
        assert "user.updated" in actions


class TestSelfPasswordChange:
    async def test_wrong_current_password_400(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        response = await client.post(
            "/api/v1/users/me/password",
            headers=headers,
            json={"current_password": "yanlis-parola", "new_password": "yeni-guclu-parola-456"},
        )
        assert response.status_code == 400
        assert response.json()["code"] == "wrong_current_password"

    async def test_successful_change_and_relogin(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        new_password = "yeni-guclu-parola-456"  # noqa: S105
        response = await client.post(
            "/api/v1/users/me/password",
            headers=headers,
            json={"current_password": TEST_ADMIN_PASSWORD, "new_password": new_password},
        )
        assert response.status_code == 200
        assert response.json()["result"] == "updated"
        # Eski parola artık çalışmaz
        old_login = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": TEST_ADMIN_PASSWORD},
        )
        assert old_login.status_code == 401
        # Yeni parola çalışır
        new_login = await client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": new_password}
        )
        assert new_login.status_code == 200

    async def test_viewer_can_change_own_password(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        await create_user(client, admin_headers, username="plain-viewer")
        viewer_headers = await login_headers_for(
            client, username="plain-viewer", password=TEST_USER_PASSWORD
        )
        new_password = "viewer-yeni-parola-789"  # noqa: S105
        response = await client.post(
            "/api/v1/users/me/password",
            headers=viewer_headers,
            json={"current_password": TEST_USER_PASSWORD, "new_password": new_password},
        )
        assert response.status_code == 200

    async def test_weak_new_password_422(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        response = await client.post(
            "/api/v1/users/me/password",
            headers=headers,
            json={"current_password": TEST_ADMIN_PASSWORD, "new_password": "kisa"},
        )
        assert response.status_code == 422

    async def test_password_change_audited_without_secret(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        new_password = "yeni-guclu-parola-456"  # noqa: S105
        await client.post(
            "/api/v1/users/me/password",
            headers=headers,
            json={"current_password": TEST_ADMIN_PASSWORD, "new_password": new_password},
        )
        actions = await actions_via_global_sessionmaker()
        assert "user.password_changed" in actions
        assert new_password not in actions
        assert TEST_ADMIN_PASSWORD not in actions


class TestAdminPasswordReset:
    async def test_self_reset_via_admin_route_409(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        me = await client.get("/api/v1/auth/me", headers=admin_headers)
        admin_id = me.json()["id"]
        response = await client.post(
            f"/api/v1/users/{admin_id}/password",
            headers=admin_headers,
            json={"new_password": "yeni-guclu-parola-456"},
        )
        assert response.status_code == 409
        assert response.json()["code"] == "use_self_endpoint"

    async def test_admin_resets_other_users_password(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        user = await create_user(client, admin_headers, username="forgot-pw")
        reset_password = "sifirlanan-parola-246"  # noqa: S105
        response = await client.post(
            f"/api/v1/users/{user['id']}/password",
            headers=admin_headers,
            json={"new_password": reset_password},
        )
        assert response.status_code == 200
        # Eski parola çalışmaz
        old_login = await client.post(
            "/api/v1/auth/login",
            json={"username": "forgot-pw", "password": TEST_USER_PASSWORD},
        )
        assert old_login.status_code == 401
        # Yeni parola çalışır
        new_login = await client.post(
            "/api/v1/auth/login",
            json={"username": "forgot-pw", "password": reset_password},
        )
        assert new_login.status_code == 200

    async def test_reset_password_audited(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        user = await create_user(client, admin_headers, username="reset-audit")
        await client.post(
            f"/api/v1/users/{user['id']}/password",
            headers=admin_headers,
            json={"new_password": "sifirlanan-parola-246"},
        )
        actions = await actions_via_global_sessionmaker()
        assert "user.password_reset" in actions


class TestSamePasswordRejected:
    """Bulgu kapatma (8-test F2): aynı parola değişimi "rotasyon" yanılsaması üretmesin."""

    async def test_self_change_same_password_422(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        response = await client.post(
            "/api/v1/users/me/password",
            headers=headers,
            json={"current_password": TEST_ADMIN_PASSWORD, "new_password": TEST_ADMIN_PASSWORD},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "same_password"

    async def test_admin_reset_same_password_422(self, make_fresh_client) -> None:
        client = await make_fresh_client()
        admin_headers = await login_headers_for(
            client, username="admin", password=TEST_ADMIN_PASSWORD
        )
        user = await create_user(client, admin_headers, username="same-pw-user")
        response = await client.post(
            f"/api/v1/users/{user['id']}/password",
            headers=admin_headers,
            json={"new_password": TEST_USER_PASSWORD},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "same_password"
