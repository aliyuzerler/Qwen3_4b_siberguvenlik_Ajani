"""Test ortak sabitleri ve yardımcıları.

Kurallar (AGENTS.md §7):
- Testlerde gerçek Wazuh / Ollama / PostgreSQL kullanılmaz.
- DB: sqlite+aiosqlite (tmp_path altında dosya bazlı).
- Secret'lar: yalnızca test değeri; asla gerçek credential kullanılmaz.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.core.config import Settings
from app.core.db import dispose_engine
from app.main import create_app

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
