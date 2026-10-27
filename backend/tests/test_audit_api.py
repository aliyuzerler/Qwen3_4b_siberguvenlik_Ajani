"""Audit API testleri (Faz 05) — admin erişimi + append-only kanıtı."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import status
from sqlalchemy import select

from app.core.db import get_sessionmaker
from app.models.audit import AuditLog
from tests.conftest import TEST_ADMIN_PASSWORD, login_and_headers

pytestmark = pytest.mark.asyncio


class TestAuditAccess:
    async def test_admin_can_list_audit_with_pagination(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        # Girişler audit üretir: bootstrap + login.success (+ login.failed)
        await client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": "yanlış-1"}
        )
        await client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": TEST_ADMIN_PASSWORD}
        )
        headers = await login_and_headers(client)
        response = await client.get("/api/v1/audit", headers=headers, params={"page_size": 2})
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["page_size"] == 2
        assert body["total"] >= 3  # bootstrap + failed + success
        assert len(body["items"]) == 2
        entry = body["items"][0]
        assert set(entry) >= {"id", "created_at", "actor", "action"}

    async def test_audit_pagination_page2(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        for index in range(5):
            await client.post(
                "/api/v1/auth/login", json={"username": "admin", "password": f"yanlış-{index}"}
            )
        headers = await login_and_headers(client)
        page1 = (
            await client.get("/api/v1/audit", headers=headers, params={"page": 1, "page_size": 3})
        ).json()
        page2 = (
            await client.get("/api/v1/audit", headers=headers, params={"page": 2, "page_size": 3})
        ).json()
        assert len(page1["items"]) == 3
        assert len(page2["items"]) >= 1
        ids1 = {item["id"] for item in page1["items"]}
        ids2 = {item["id"] for item in page2["items"]}
        assert ids1.isdisjoint(ids2)

    async def test_audit_rejects_invalid_pagination(self, make_client: Any) -> None:
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        headers = await login_and_headers(client)
        response = await client.get("/api/v1/audit", headers=headers, params={"page_size": 500})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


class TestAppendOnly:
    async def test_no_update_delete_code_paths_for_audit_log(self) -> None:
        """append-only kanıtı: app içinde audit_log üzerinde UPDATE/DELETE yok.

        AGENTS.md §4: "Ajan kendi audit kayıtlarını değiştirememeli."
        Kaynak taraması ile kanıtlanır (whitelist: yalnızca model tanımı).
        """
        import re
        from pathlib import Path

        app_dir = Path(__file__).resolve().parents[1] / "app"
        pattern = re.compile(
            r"(update|delete)\s*\(\s*[A-Za-z_]*AuditLog", re.IGNORECASE
        )
        offenders: list[str] = []
        for path in app_dir.rglob("*.py"):
            content = path.read_text(encoding="utf-8")
            for match in pattern.finditer(content):
                offenders.append(f"{path.name}: {match.group(0)}")
        assert offenders == [], f"audit_log yazma/okuma dışı erişim: {offenders}"

    async def test_audit_rows_persist_independent_of_user(self, make_client: Any) -> None:
        """audit_log'da actor FK YOK — kullanıcı silinse bile iz kalır."""
        client = await make_client(admin_bootstrap_password=TEST_ADMIN_PASSWORD)
        await client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": TEST_ADMIN_PASSWORD}
        )
        async with get_sessionmaker()() as session:
            rows = (await session.scalars(select(AuditLog))).all()
            assert rows, "en az bir audit kaydı olmalı"
            # actor alanı dolu ve action whitelist'ten
            actions = {row.action for row in rows}
            assert actions.issubset(
                {
                    "auth.login.success",
                    "auth.login.failed",
                    "auth.login.rate_limited",
                    "auth.refresh.success",
                    "auth.refresh.failed",
                    "auth.bootstrap.admin_created",
                }
            )
