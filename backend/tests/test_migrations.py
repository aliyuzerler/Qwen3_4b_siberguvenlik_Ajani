"""Alembic migration testleri (Faz 03).

Kapsam (phases/03 test promptu): "migration rollback senaryoları".
Gerçek alembic CLI'ı subprocess ile çalıştırır (sync bağlam; env.py async motor
kullanır). DATABASE_URL test izolasyonlu sqlite dosyasına yönlendirilir;
secret'lar yalnızca test değeridir (AGENTS.md §7).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from tests.conftest import TEST_JWT_SECRET

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _run_alembic(db_url: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DATABASE_URL"] = db_url
    env["JWT_SECRET"] = TEST_JWT_SECRET
    return subprocess.run(  # noqa: S603  # girdiler denetimli: sys.executable + sabit argümanlar
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


async def _table_names(db_url: str) -> list[str]:
    engine = create_async_engine(db_url)
    try:
        async with engine.connect() as connection:
            rows = await connection.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
            return sorted(str(row[0]) for row in rows)
    finally:
        await engine.dispose()


async def _table_columns(db_url: str, table: str) -> list[str]:
    engine = create_async_engine(db_url)
    try:
        async with engine.connect() as connection:
            rows = await connection.execute(text(f"PRAGMA table_info({table})"))  # noqa: S608
            return [str(row[1]) for row in rows]
    finally:
        await engine.dispose()


@pytest.fixture
def migration_db(tmp_path: Path) -> str:
    return f"sqlite+aiosqlite:///{tmp_path}/migration.db"


class TestMigrations:
    async def test_upgrade_creates_events_table(self, migration_db: str) -> None:
        result = _run_alembic(migration_db, "upgrade", "head")
        assert result.returncode == 0, result.stderr
        tables = await _table_names(migration_db)
        assert "events" in tables
        assert "alembic_version" in tables

    async def test_upgraded_schema_has_required_columns(self, migration_db: str) -> None:
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        columns = await _table_columns(migration_db, "events")
        for required in (
            "id",
            "schema_version",
            "source",
            "alert_id",
            "idempotency_key",
            "timestamp",
            "received_at",
            "rule_id",
            "rule_level",
            "rule_description",
            "rule_groups",
            "fingerprint",
            "seen_count",
            "variant_count",
            "raw_alert",
        ):
            assert required in columns, f"sütun eksik: {required}"

    async def test_downgrade_rolls_back_cleanly(self, migration_db: str) -> None:
        # rollback senaryosu: upgrade → downgrade → tablo yok, sonra tekrar upgrade
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        down = _run_alembic(migration_db, "downgrade", "base")
        assert down.returncode == 0, down.stderr
        assert "events" not in await _table_names(migration_db)

    async def test_rollback_then_reupgrade_recovers(self, migration_db: str) -> None:
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        assert _run_alembic(migration_db, "downgrade", "base").returncode == 0
        again = _run_alembic(migration_db, "upgrade", "head")
        assert again.returncode == 0, again.stderr
        assert "events" in await _table_names(migration_db)

    async def test_single_head_revision(self, migration_db: str) -> None:
        # Çatallı migration zinciri olmamalı (sürümlendirme disiplini).
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        heads = _run_alembic(migration_db, "heads")
        assert len(heads.stdout.strip().splitlines()) == 1
