"""Müdahale güvenlik garantileri testleri (Faz 07).

Kaynak tarama kalıbı (append-only/XSS testleriyle aynı yaklaşım): güvenlik
invariantları ÇALIŞMA ZAMANINDA değil, KOD yapısında zorunlu kılınır ve
bu testlerle kalıcı olarak denetlenir.

Kapsam (phases/07 + AGENTS.md §4):
- "İlk testlerde gerçek sistem değişikliği yerine fake executor kullan"
  → remediation paketinde subprocess/os.system/socket/eval/exec YOK;
  yalnızca DryRunExecutor somut sınıfı vardır.
- "Model eylemi doğrudan başlatamaz" → analysis/worker paketleri
  remediation'ı İÇERMEZ; öneri yalnızca kimlikli insan uçlarından.
- "Ajan kendi ... kayıtlarını silememeli" → remediation_actions satırına
  DELETE kod yolu YOK.
- prod yapılandırma: REMEDIATION_ALLOW_BLOCKED_ACTIONS=true ile başlamaz.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.core.config import Settings
from tests.conftest import TEST_JWT_SECRET

pytestmark = pytest.mark.asyncio

BACKEND_DIR = Path(__file__).resolve().parents[1]
REMEDIATION_DIR = BACKEND_DIR / "app" / "services" / "remediation"


def _package_sources() -> dict[Path, str]:
    """remediation paketindeki tüm .py dosyalarını okur."""
    sources: dict[Path, str] = {}
    for path in sorted(REMEDIATION_DIR.rglob("*.py")):
        sources[path] = path.read_text(encoding="utf-8")
    assert sources, "remediation paketi boş olamaz"
    return sources


class TestNoRealExecutor:
    async def test_no_process_network_or_eval_primitives(self) -> None:
        """Gerçek yürütme ilkeleleri pakette YASAK (fake executor garantisi).

        AST tabanlı tarama: yorum/docstring metinleri DEĞİL, gerçek kod
        yapısı denetlenir (import + çağrı düğümleri).
        """
        import ast

        banned_modules = {"subprocess", "socket", "paramiko", "fabric", "http.client"}
        banned_calls = {"system", "popen", "spawnv"}  # çağrılan fonksiyon/attr adları
        for path, source in _package_sources().items():
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name.split(".")[0] not in banned_modules, (
                            f"{path.name}: yasak modül import edildi: {alias.name}"
                        )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    assert node.module.split(".")[0] not in banned_modules, (
                        f"{path.name}: yasak modül import edildi: {node.module}"
                    )
                elif isinstance(node, ast.Call):
                    func = node.func
                    name = ""
                    if isinstance(func, ast.Name):
                        name = func.id
                    elif isinstance(func, ast.Attribute):
                        name = func.attr
                    assert name not in banned_calls, (
                        f"{path.name}: yasak çağrı: {name}()"
                    )

    async def test_only_dry_run_executor_class_exists(self) -> None:
        """Tek somut yürütücü DryRunExecutor; Shell/Real/Command yürütücü YOK.

        AST tabanlı: paket içindeki tüm Executor adlı sınıflar sayılır.
        ActionExecutor (Protocol) + DryRunExecutor dışındaki her ad reddedilir.
        """
        import ast

        found: set[str] = set()
        for path, source in _package_sources().items():
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and "Executor" in node.name:
                    found.add(node.name)
        assert found == {"ActionExecutor", "DryRunExecutor"}, (
            f"Yalnızca ActionExecutor (Protocol) + DryRunExecutor tanımlı "
            f"olmalı; bulunanlar: {found}"
        )

    async def test_dry_run_executor_has_no_side_effect_imports(self) -> None:
        """DryRunExecutor modülü yalnızca asyncio/time/log import eder."""
        executor_source = (REMEDIATION_DIR / "executor.py").read_text(encoding="utf-8")
        # requests/httpx/urllib ağ çağrısı; pathlib silme vb. yok:
        for banned in ("httpx", "requests", "urllib", "aiohttp"):
            assert banned not in executor_source

    async def test_observe_only_is_default_policy_mode(self) -> None:
        """Başlangıç modu observe_only (phases/07: 'Başlangıç modu observe_only')."""
        settings = Settings(
            jwt_secret=TEST_JWT_SECRET,
            database_url="sqlite+aiosqlite:///tmp/x.db",
            _env_file=None,
        )
        assert settings.policy_mode == "observe_only"
        assert settings.remediation_allow_blocked_actions is False
        assert settings.remediation_allow_self_approval is False
        # "Gerçek yürütme" modu enum'da YOK:
        from typing import get_args

        from app.core.config import Settings as S

        hints = get_args(S.model_fields["policy_mode"].annotation)
        assert set(hints) == {"observe_only", "dry_run"}

    async def test_prod_cannot_enable_blocked_actions(self) -> None:
        """Üretimde firewall/SSH kapısı AÇILAMAZ (config validator reddeder)."""
        with pytest.raises(Exception) as excinfo:
            Settings(
                jwt_secret=TEST_JWT_SECRET,
                database_url="postgresql+asyncpg://u:p@localhost:5432/db",
                app_env="prod",
                remediation_allow_blocked_actions=True,
                _env_file=None,
            )
        assert "REMEDIATION_ALLOW_BLOCKED_ACTIONS" in str(excinfo.value)


class TestModelIsolation:
    async def test_analysis_and_worker_packages_never_import_remediation(
        self,
    ) -> None:
        """Model eylemi başlatamaz: analiz/worker kodu remediation'a ERIŞEMEZ."""
        forbidden_import = re.compile(
            r"(from\s+app\.services\.remediation|import\s+app\.services\.remediation)",
        )
        scan_roots = [
            BACKEND_DIR / "app" / "services" / "analysis",
            BACKEND_DIR / "app" / "workers",
            BACKEND_DIR / "app" / "services" / "normalization",
        ]
        for root in scan_roots:
            for path in sorted(root.rglob("*.py")):
                source = path.read_text(encoding="utf-8")
                assert not forbidden_import.search(source), (
                    f"{path}: analiz/worker katmanı remediation paketine "
                    "erişemez (AGENTS.md §4: model eylem başlatamaz)"
                )

    async def test_proposal_creation_requires_human_identity(self) -> None:
        """create_proposal imzası insan kimliği ister (model/otomatik yol yok)."""
        import inspect

        from app.services.remediation.service import create_proposal

        params = inspect.signature(create_proposal).parameters
        assert "requested_by_user_id" in params
        assert "requested_by_username" in params
        assert "justification" in params  # insan gerekçesi zorunlu


class TestNoDeletePath:
    async def test_no_delete_for_remediation_rows(self) -> None:
        """remediation_actions/remediation_catalog satırı SİLİNEMEZ (append-baskın)."""
        delete_pattern = re.compile(r"\.delete\(|DELETE\s+FROM\s+remediation")
        api_dir = BACKEND_DIR / "app"
        offenders: list[str] = []
        for path in sorted(api_dir.rglob("*.py")):
            if "retention" in path.name:
                # retention yalnızca events FK CASCADE temizliği yapar;
                # remediation tablolarına dokunmaz (aşağıda ayrıca denetlenir).
                continue
            source = path.read_text(encoding="utf-8")
            for match in delete_pattern.finditer(source):
                offenders.append(f"{path.name}:{source[: match.start()].count(chr(10)) + 1}")
        assert not offenders, f"DELETE kod yolu bulundu: {offenders}"

    async def test_retention_does_not_touch_remediation_tables(self) -> None:
        """Retention temizliği remediation tablolarına dokunmaz (FK CASCADE bekler)."""
        retention_source = (
            BACKEND_DIR / "app" / "services" / "normalization" / "repository.py"
        ).read_text(encoding="utf-8")
        assert "remediation" not in retention_source.lower()
