"""Auth API uç testleri (Faz 05).

Kapsam (phases/05 test promptu): oturum açma, token çifti, /auth/me,
bootstrap davranışı, audit kayıtları, genel hata mesajı (kullanıcı/parola
ayırt edilemez), secret sızması yokluğu.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy import select

from app.core.db import get_sessionmaker
from app.models.audit import AuditLog
from app.models.user import User
from tests.conftest import TEST_ADMIN_PASSWORD, login_and_headers

pytestmark = pytest.mark.asyncio


class TestLogin:
    async def test_login_success_returns_token_pair(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        response = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": TEST_ADMIN_PASSWORD},
        )
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"] and body["refresh_token"]
        assert body["expires_in"] > 0

    async def test_login_wrong_password_generic_error(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        response = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "kesinlikle-yanlış"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        detail = response.json()["detail"]
        assert "Kullanıcı adı veya parola hatalı" in detail
        # Yanıtta parola değeri ASLA geri dönmez
        assert "kesinlikle-yanlış" not in response.text

    async def test_login_unknown_user_same_generic_error(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        response = await client.post(
            "/api/v1/auth/login",
            json={"username": "yok-boyle-kullanici", "password": "her-neyse"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        detail = response.json()["detail"]
        assert detail == "Kullanıcı adı veya parola hatalı."

    async def test_login_case_insensitive_username(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        response = await client.post(
            "/api/v1/auth/login",
            json={"username": "  ADMIN  ", "password": TEST_ADMIN_PASSWORD},
        )
        assert response.status_code == status.HTTP_200_OK

    async def test_login_updates_last_login(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": TEST_ADMIN_PASSWORD},
        )
        async with get_sessionmaker()() as session:
            user = (await session.scalars(select(User).where(User.username == "admin"))).first()
            assert user is not None
            assert user.last_login_at is not None

    async def test_login_validation_rejects_bad_payload(self, client: AsyncClient) -> None:
        response = await client.post("/api/v1/auth/login", json={"username": ""})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_login_without_bootstrap_password_cannot_enter(
        self, make_client: Any
    ) -> None:
        """ADMIN_BOOTSTRAP_PASSWORD yoksa kullanıcı hiç oluşmaz → giriş 401."""
        client = await make_client(admin_bootstrap_password=None)  # bootstrap parolası YOK
        response = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "deneme-1234"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestMe:
    async def test_me_requires_token(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_me_returns_current_user(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        headers = await login_and_headers(client)
        response = await client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["username"] == "admin"
        assert body["role"] == "admin"
        # Parola/hash alanı yanıtta YOK
        assert "password" not in body and "password_hash" not in body


class TestBootstrap:
    async def test_bootstrap_creates_admin_once(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        async with get_sessionmaker()() as session:
            users = (await session.scalars(select(User))).all()
            assert len(users) == 1
            admin = users[0]
            assert admin.role == "admin"
            assert admin.is_active is True
            # Parola hash'lenmiştir; düz metin saklanmaz
            assert admin.password_hash.startswith("$argon2id$")
            assert TEST_ADMIN_PASSWORD not in admin.password_hash
        del client

    async def test_bootstrap_skipped_when_users_exist(self, make_client: Any) -> None:
        """İkinci açılışta mevcut kullanıcı varsa bootstrap YAPILMAZ."""
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        # Aynı DB'ye bağlı ikinci bootstrap çağrısı (simülasyon):
        from app.services.security import bootstrap_admin_if_empty

        async with get_sessionmaker()() as session:
            created = await bootstrap_admin_if_empty(
                session, username="admin", password="başka-parola"
            )
            assert created is False  # kullanıcı zaten var → yok sayılır
        del client


class TestAuditTrail:
    async def test_login_writes_audit_rows(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": TEST_ADMIN_PASSWORD}
        )
        await client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": "yanlış-deneme"}
        )
        async with get_sessionmaker()() as session:
            actions = {
                row.action for row in (await session.scalars(select(AuditLog))).all()
            }
        assert "auth.login.success" in actions
        assert "auth.login.failed" in actions

    async def test_audit_never_records_password_value(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": TEST_ADMIN_PASSWORD}
        )
        async with get_sessionmaker()() as session:
            rows = (await session.scalars(select(AuditLog))).all()
            dumped = {str(row.detail) + str(row.note) for row in rows}
        for text in dumped:
            assert TEST_ADMIN_PASSWORD not in text

    async def test_bootstrap_audited(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        async with get_sessionmaker()() as session:
            actions = {
                row.action for row in (await session.scalars(select(AuditLog))).all()
            }
        assert "auth.bootstrap.admin_created" in actions
        del client
