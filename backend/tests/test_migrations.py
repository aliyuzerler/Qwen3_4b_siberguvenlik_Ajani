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


async def _table_sql(db_url: str, table: str) -> str:
    engine = create_async_engine(db_url)
    try:
        async with engine.connect() as connection:
            row = (
                await connection.execute(
                    text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:t"),
                    {"t": table},
                )
            ).first()
            return str(row[0]) if row else ""
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

    # --- Faz 04: analyses tablosu migration'ı -------------------------------

    async def test_upgrade_head_creates_analyses_table(self, migration_db: str) -> None:
        """0002_analyses: tablo var, zorunlu sütunlar ve CHECK kısıtları yerinde."""
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        tables = await _table_names(migration_db)
        assert "analyses" in tables
        columns = await _table_columns(migration_db, "analyses")
        for required in (
            "id",
            "event_id",
            "schema_version",
            "status",
            "ai_assessment",
            "confidence",
            "summary",
            "evidence",
            "alternative_explanations",
            "recommended_next_steps",
            "requires_human_review",
            "error_code",
            "error_message",
            "model_tag",
            "model_quantization",
            "prompt_template_version",
            "prompt_chars",
            "context_chars",
            "context_truncated",
            "duration_ms",
            "retries_used",
            "finished_at",
            "created_at",
        ):
            assert required in columns, f"analyses sütunu eksik: {required}"
        ddl = await _table_sql(migration_db, "analyses")
        assert "FOREIGN KEY" in ddl.upper()  # events FK (CASCADE)
        assert "ck_analyses_status" in ddl
        assert "ck_analyses_confidence" in ddl
        assert "ck_analyses_completed_has_assessment" in ddl

    async def test_downgrade_drops_analyses_before_events(self, migration_db: str) -> None:
        """Geri dönüş yolu: head'den iki adım downgrade analyses'i düşürür; events kalır.

        Faz 05 notu: head artık 0003_auth; "analyses" adımı için downgrade
        hedefi açıkça 0001_events olarak verilir (tek adım -1 artık 0002'ye
        döner — analyses hâlâ yerinde olur, bu beklenen davranıştır).
        """
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        down = _run_alembic(migration_db, "downgrade", "0001_events")
        assert down.returncode == 0, down.stderr
        tables = await _table_names(migration_db)
        assert "analyses" not in tables
        assert "events" in tables  # önceki faz tablosu etkilenmez

    # --- Faz 05: users + audit_log migration'ı ------------------------------

    async def test_upgrade_head_creates_auth_tables(self, migration_db: str) -> None:
        """0003_auth: users + audit_log tabloları, sütunlar ve CHECK kısıtları."""
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        tables = await _table_names(migration_db)
        assert "users" in tables
        assert "audit_log" in tables

        user_columns = await _table_columns(migration_db, "users")
        for required in (
            "id",
            "username",
            "password_hash",
            "role",
            "is_active",
            "created_at",
            "last_login_at",
        ):
            assert required in user_columns, f"users sütunu eksik: {required}"
        user_ddl = await _table_sql(migration_db, "users")
        assert "ck_users_role" in user_ddl
        assert "UNIQUE" in user_ddl.upper()  # username unique

        audit_columns = await _table_columns(migration_db, "audit_log")
        for required in (
            "id",
            "created_at",
            "actor",
            "actor_user_id",
            "action",
            "resource",
            "detail",
            "client_ip",
            "request_id",
            "note",
        ):
            assert required in audit_columns, f"audit_log sütunu eksik: {required}"

    async def test_downgrade_auth_drops_tables_before_analyses(self, migration_db: str) -> None:
        """head → 0002: users ve audit_log düşer; analyses/events etkilenmez."""
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        down = _run_alembic(migration_db, "downgrade", "0002_analyses")
        assert down.returncode == 0, down.stderr
        tables = await _table_names(migration_db)
        assert "users" not in tables
        assert "audit_log" not in tables
        assert "analyses" in tables
        assert "events" in tables

    async def test_password_hash_column_never_stores_plaintext_schema_note(
        self, migration_db: str
    ) -> None:
        """users.password_hash sütun adı düz metin parola sütunu DEĞİLDİR (şema kanıtı)."""
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        columns = await _table_columns(migration_db, "users")
        assert "password" not in columns, "düz metin parola sütunu olmamalı"
        assert "password_hash" in columns

    # --- Faz 06: korelasyon tabloları migration'ı ----------------------------

    async def test_upgrade_head_creates_correlation_tables(
        self, migration_db: str
    ) -> None:
        """0004_correlations: üç tablo, sütunlar, CHECK + UNIQUE + FK kısıtları."""
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        tables = await _table_names(migration_db)
        assert "correlation_rules" in tables
        assert "correlations" in tables
        assert "correlation_events" in tables

        rule_columns = await _table_columns(migration_db, "correlation_rules")
        for required in (
            "key",
            "name",
            "description",
            "version",
            "kind",
            "params",
            "enabled",
            "created_at",
            "updated_at",
        ):
            assert required in rule_columns, f"correlation_rules sütunu eksik: {required}"
        rule_ddl = await _table_sql(migration_db, "correlation_rules")
        assert "ck_correlation_rules_version" in rule_ddl
        assert "ck_correlation_rules_kind" in rule_ddl

        corr_columns = await _table_columns(migration_db, "correlations")
        for required in (
            "id",
            "rule_key",
            "rule_version",
            "dedup_key",
            "window_start",
            "window_end",
            "event_count",
            "max_rule_level",
            "evidence",
            "hit_count",
            "first_hit_at",
            "last_hit_at",
            "created_at",
        ):
            assert required in corr_columns, f"correlations sütunu eksik: {required}"
        corr_ddl = await _table_sql(migration_db, "correlations")
        assert "UNIQUE" in corr_ddl.upper()  # dedup_key UNIQUE (tekrar yönetimi)
        assert "ck_correlations_event_count" in corr_ddl
        assert "ck_correlations_hit_count" in corr_ddl
        assert "ck_correlations_max_rule_level" in corr_ddl
        assert "FOREIGN KEY" in corr_ddl.upper()  # rule_key FK

        link_ddl = await _table_sql(migration_db, "correlation_events")
        assert link_ddl.upper().count("FOREIGN KEY") == 2  # her iki FK CASCADE
        assert "ON DELETE CASCADE" in link_ddl.upper()

    async def test_downgrade_correlations_drops_all_three_tables(
        self, migration_db: str
    ) -> None:
        """Geri dönüş yolu: head → 0003 korelasyon tabloları düşer; auth kalır."""
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        down = _run_alembic(migration_db, "downgrade", "0003_auth")
        assert down.returncode == 0, down.stderr
        tables = await _table_names(migration_db)
        assert "correlations" not in tables
        assert "correlation_events" not in tables
        assert "correlation_rules" not in tables
        assert "users" in tables and "audit_log" in tables  # önceki faz etkilenmez

    async def test_correlation_roundtrip_reupgrade(
        self, migration_db: str
    ) -> None:
        """0004 → 0003 → 0004 turu veri şemasını bozmaz."""
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        assert _run_alembic(migration_db, "downgrade", "0003_auth").returncode == 0
        again = _run_alembic(migration_db, "upgrade", "head")
        assert again.returncode == 0, again.stderr
        tables = await _table_names(migration_db)
        assert {"correlation_rules", "correlations", "correlation_events"} <= set(tables)


class TestRemediationMigrations:
    """Faz 07: remediation_catalog + remediation_actions migration testleri."""

    async def test_upgrade_head_creates_remediation_tables(
        self, migration_db: str
    ) -> None:
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        tables = await _table_names(migration_db)
        assert "remediation_catalog" in tables
        assert "remediation_actions" in tables

    async def test_remediation_actions_schema_required_columns(
        self, migration_db: str
    ) -> None:
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        columns = await _table_columns(migration_db, "remediation_actions")
        for required in (
            "id",
            "idempotency_key",
            "action_type",
            "action_title",
            "risk_level",
            "status",
            "requested_by_user_id",
            "requested_by_username",
            "justification",
            "params",
            "evidence",
            "policy_decision",
            "approved_by_user_id",
            "approved_by_username",
            "approved_at",
            "rejected_by_username",
            "rejected_reason",
            "execution_key",
            "executed_at",
            "execution_count",
            "execution_result",
            "execution_error",
            "created_at",
            "updated_at",
        ):
            assert required in columns, f"remediation_actions sütunu eksik: {required}"
        ddl = await _table_sql(migration_db, "remediation_actions")
        assert "UNIQUE" in ddl.upper()  # idempotency_key + execution_key
        assert "ck_remediation_actions_status" in ddl
        assert "ck_remediation_actions_action_type" in ddl
        assert "ck_remediation_actions_risk_level" in ddl
        assert "FOREIGN KEY" in ddl.upper()  # users FK (SET NULL)

    async def test_remediation_downgrade_drops_both_tables(
        self, migration_db: str
    ) -> None:
        """Geri dönüş yolu: head → 0004 iki remediation tablosu düşer."""
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        down = _run_alembic(migration_db, "downgrade", "0004_correlations")
        assert down.returncode == 0, down.stderr
        tables = await _table_names(migration_db)
        assert "remediation_actions" not in tables
        assert "remediation_catalog" not in tables
        # Önceki faz tabloları etkilenmez:
        assert "correlations" in tables
        assert "users" in tables

    async def test_remediation_roundtrip_reupgrade(self, migration_db: str) -> None:
        """0005 → 0004 → 0005 turu şemayı bozmaz."""
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        assert _run_alembic(migration_db, "downgrade", "0004_correlations").returncode == 0
        again = _run_alembic(migration_db, "upgrade", "head")
        assert again.returncode == 0, again.stderr
        tables = await _table_names(migration_db)
        assert {"remediation_catalog", "remediation_actions"} <= set(tables)

    # --- Faz 08: rate_limit_counters (paylaşımlı fren deposu) ----------------

    async def test_upgrade_head_creates_rate_limit_counters(self, migration_db: str) -> None:
        """0006_hardening: birleşik PK + pencere indeksi yerinde."""
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        tables = await _table_names(migration_db)
        assert "rate_limit_counters" in tables
        columns = await _table_columns(migration_db, "rate_limit_counters")
        for required in ("key", "window_start", "hit_count"):
            assert required in columns, f"rate_limit_counters sütunu eksik: {required}"
        ddl = await _table_sql(migration_db, "rate_limit_counters")
        # Birleşik birincil anahtar (key, window_start)
        assert "PRIMARY KEY" in ddl.upper()
        assert "window_start" in ddl.lower()

    async def test_hardening_downgrade_drops_rate_limit_table(self, migration_db: str) -> None:
        """Geri dönüş yolu: head → 0005 rate_limit_counters düşer; remediation kalır."""
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        down = _run_alembic(migration_db, "downgrade", "0005_remediation")
        assert down.returncode == 0, down.stderr
        tables = await _table_names(migration_db)
        assert "rate_limit_counters" not in tables
        # Önceki faz tabloları etkilenmez:
        assert "remediation_actions" in tables
        assert "users" in tables

    async def test_hardening_roundtrip_reupgrade(self, migration_db: str) -> None:
        """0006 → 0005 → 0006 turu şemayı bozmaz."""
        assert _run_alembic(migration_db, "upgrade", "head").returncode == 0
        assert _run_alembic(migration_db, "downgrade", "0005_remediation").returncode == 0
        again = _run_alembic(migration_db, "upgrade", "head")
        assert again.returncode == 0, again.stderr
        assert "rate_limit_counters" in await _table_names(migration_db)
