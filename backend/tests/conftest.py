"""Test ortak sabitleri ve yardımcıları.

Kurallar (AGENTS.md §7):
- Testlerde gerçek Wazuh / Ollama / PostgreSQL kullanılmaz.
- DB: sqlite+aiosqlite (tmp_path altında dosya bazlı).
- Secret'lar: yalnızca test değeri; asla gerçek credential kullanılmaz.
- Tüm alert verisi SENTETİKTİR (RFC 5737 doküman aralıkları, örnek alanlar).
- Ollama istemcisi: MockOllamaClient (protokol uyumlu); varsayılan
  ollama_base_url deterministik olarak ERİŞİLEMEZ porttur (127.0.0.1:9) —
  /ready testleri kullanıcının makinesinde gerçek Ollama olsa bile
  deterministiktir.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.models  # noqa: F401  # Event/Analysis'i Base.metadata'ya kaydeder
from app.core.config import Settings
from app.core.db import Base, dispose_engine, register_sqlite_fk_pragma
from app.main import create_app
from app.services.analysis.errors import AnalysisError
from app.services.wazuh.models import WazuhAlert

# YALNIZCA TEST İÇİN sahte secret (gerçek değildir, repoda örnek olarak işaretlidir)
TEST_JWT_SECRET = "test-sadece-sahte-secret-0123456789abcdef-0123456789abcdef"  # noqa: S105

# Deterministik erişilemez Ollama portu (discard — bağlantı anında reddedilir)
UNREACHABLE_OLLAMA_URL = "http://127.0.0.1:9"


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    """Test için izole Settings üretir; gerçek .env dosyasını okumaz."""
    values: dict[str, object] = {
        "app_env": "dev",
        "jwt_secret": TEST_JWT_SECRET,
        "database_url": f"sqlite+aiosqlite:///{tmp_path}/test.db",
        "log_level": "INFO",
        "cors_origins": "",
        "ollama_base_url": UNREACHABLE_OLLAMA_URL,
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
    register_sqlite_fk_pragma(engine)  # FK CASCADE, PG semantiğiyle aynı olsun
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


# --- Faz 04: Ollama mock istemcisi ve sentetik model çıktısı ---------------


def make_valid_model_output(
    alert_id: str = "1792974900.123456", **overrides: Any
) -> str:
    """SENTETİK GEÇERLİ model çıktısı (JSON metni) üretir."""
    payload: dict[str, Any] = {
        "schema_version": 1,
        "alert_ids": [alert_id],
        "summary": "SSH servisine karşı brute force denemesi gözlemlendi.",
        "assessment": "suspicious",
        "confidence": 0.7,
        "evidence": [
            {"field": "rule.description", "value": "sshd: Brute force"},
            {"field": "src_ip", "value": "203.0.113.7"},
        ],
        "alternative_explanations": ["Yanlış yapılandırılmış servis taraması"],
        "recommended_next_steps": ["review_full_logs", "correlate_related_events"],
        "requires_human_review": True,
    }
    payload.update(overrides)
    return json.dumps(payload, ensure_ascii=False)


class MockOllamaClient:
    """OllamaClient protokolünün test uydusu.

    - responses=None (varsayılan): prompt'taki alert_id'yi okuyup GEÇERLİ
      çıktı üretir (gerçek modelin sözleşmeye uyması senaryosu).
    - responses listesi verilirse: sırayla tüketilir; str → döndürülür,
      AnalysisError → fırlatılır; liste tükenirse SON eleman tekrarlanır.
    - fail_first_n: ilk N generate çağrısı OllamaUnavailableError fırlatır
      (worker loop dayanıklılık senaryosu).
    - calls: generate çağrılarının kaydı (prompt injection çerçeve testi vb.)
    - health / models: /ready yoklaması ve model-missing senaryosu için.
    """

    _ALERT_ID_RE = re.compile(r'"alert_id": "([^"]+)"')

    def __init__(
        self,
        *,
        responses: list[str | AnalysisError] | None = None,
        health_error: AnalysisError | None = None,
        models: tuple[str, ...] = ("qwen3:4b",),
        latency_seconds: float = 0.0,
        fail_first_n: int = 0,
    ) -> None:
        from app.services.analysis.errors import OllamaModelMissingError

        self._missing_error_type = OllamaModelMissingError
        self.responses = responses  # None → dinamik geçerli çıktı modu
        self.health_error = health_error
        self.models = models
        self.latency_seconds = latency_seconds
        self.fail_first_n = fail_first_n
        self.calls: list[dict[str, Any]] = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        model_tag: str,
        temperature: float,
        num_predict: int,
        timeout_seconds: float,
    ) -> str:
        from app.services.analysis.errors import OllamaUnavailableError

        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "model_tag": model_tag,
                "temperature": temperature,
                "num_predict": num_predict,
            }
        )
        if self.latency_seconds > 0:
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)
            try:
                import asyncio

                await asyncio.sleep(self.latency_seconds)
            finally:
                self.in_flight -= 1
        if self.fail_first_n > 0:
            self.fail_first_n -= 1
            raise OllamaUnavailableError("Ollama'ya bağlanılamadı (sentetik, fail_first_n)")
        if self.responses is None:
            # Dinamik mod: bağlamdaki alert_id'yi yansıtan geçerli çıktı.
            match = self._ALERT_ID_RE.search(user_prompt)
            return make_valid_model_output(match.group(1) if match else "0.0")
        item = self.responses[0] if len(self.responses) == 1 else self.responses.pop(0)
        if isinstance(item, AnalysisError):
            raise item
        return item

    async def check_health(self) -> None:
        if self.health_error is not None:
            raise self.health_error

    async def ensure_model(self, model_tag: str) -> None:
        if model_tag not in self.models:
            raise self._missing_error_type(
                f"Model '{model_tag}' Ollama'da yüklü değil. Kurulum: "
                f"`ollama pull {model_tag}` komutunu çalıştırın."
            )

    async def aclose(self) -> None:
        return None
