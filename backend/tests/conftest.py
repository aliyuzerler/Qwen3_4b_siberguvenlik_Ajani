"""Test ortak sabitleri ve yardımcıları.

Kurallar (AGENTS.md §7):
- Testlerde gerçek Wazuh / Ollama / PostgreSQL kullanılmaz.
- DB: sqlite+aiosqlite (tmp_path altında dosya bazlı).
- Secret'lar: yalnızca test değeri; asla gerçek credential kullanılmaz.
- Tüm alert verisi SENTETİKTİR (RFC 5737 doküman aralıkları, örnek alanlar).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.models  # noqa: F401  # Event'i Base.metadata'ya kaydeder
from app.core.config import Settings
from app.core.db import Base, dispose_engine
from app.main import create_app
from app.services.wazuh.models import WazuhAlert

# YALNIZCA TEST İÇİN sahte secret (gerçek değildir, repoda örnek olarak işaretlidir)
TEST_JWT_SECRET = "test-sadece-sahte-secret-0123456789abcdef-0123456789abcdef"  # noqa: S105


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    """Test için izole Settings üretir; gerçek .env dosyasını okumaz."""
    values: dict[str, object] = {
        "app_env": "dev",
        "jwt_secret": TEST_JWT_SECRET,
        "database_url": f"sqlite+aiosqlite:///{tmp_path}/test.db",
        "log_level": "INFO",
        "cors_origins": "",
        "_env_file": None,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


@pytest_asyncio.fixture
async def client(tmp_path: Path) -> AsyncIterator[AsyncClient]:
    """Test istemcisi: her test için izole uygulama + sqlite DB."""
    application = create_app(make_settings(tmp_path))
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        yield http_client
    await dispose_engine()


@pytest_asyncio.fixture
async def sessionmaker_fixture(tmp_path: Path) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Depolama testleri için izole sqlite oturum fabrikası (şema create_all)."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/events.db")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    yield maker
    await engine.dispose()


def make_alert(**overrides: Any) -> WazuhAlert:
    """SENTETİK WazuhAlert üretir (test tekrarını azaltır)."""
    values: dict[str, Any] = {
        "alert_id": "1792974900.123456",
        "timestamp": datetime(2026, 10, 26, 9, 15, 0, tzinfo=UTC),
        "rule_id": "5712",
        "rule_level": 10,
        "rule_description": "sshd: Brute force trying to get access to the system.",
        "rule_groups": ["syslog", "sshd"],
        "agent_id": "001",
        "agent_name": "web-server-01",
        "location": "/var/log/auth.log",
        "decoder": "sshd",
        "manager": "wazuh-manager-01",
        "full_log": "Oct 26 09:15:00 sshd[4321]: Failed password for root",
        "src_ip": "203.0.113.7",
        "raw": {"id": "1792974900.123456"},
    }
    values.update(overrides)
    return WazuhAlert(**values)
