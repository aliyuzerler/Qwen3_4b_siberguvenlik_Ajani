"""Config doğrulama testleri (Faz 01 kabul: config validation + fail-fast)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from tests.conftest import TEST_JWT_SECRET


def _base(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "app_env": "dev",
        "jwt_secret": TEST_JWT_SECRET,
        "database_url": "sqlite+aiosqlite:///./t.db",
        "_env_file": None,
    }
    values.update(overrides)
    return values


def test_missing_jwt_secret_rejected() -> None:
    values = _base()
    values.pop("jwt_secret")
    with pytest.raises(ValidationError) as exc:
        Settings(**values)  # type: ignore[arg-type]
    assert "jwt_secret" in str(exc.value)


def test_short_jwt_secret_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        Settings(**_base(jwt_secret="kisa"))  # noqa: S106 — bilinçli geçersiz örnek değer
    assert "jwt_secret" in str(exc.value)


def test_missing_database_url_rejected() -> None:
    values = _base()
    values.pop("database_url")
    with pytest.raises(ValidationError) as exc:
        Settings(**values)  # type: ignore[arg-type]
    assert "database_url" in str(exc.value)


def test_unsupported_database_url_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        Settings(**_base(database_url="postgresql://user:pass@localhost/db"))
    assert "asyncpg" in str(exc.value)


def test_safe_defaults() -> None:
    settings = Settings(**_base())
    # AGENTS.md §4: varsayılan politika observe_only olmalıdır.
    assert settings.policy_mode == "observe_only"
    # Faz 04: model tag sabittir.
    assert settings.ollama_model_tag == "qwen3:4b"
    # Wazuh boş değerler None'a çevrilir (devre dışı).
    assert settings.wazuh_indexer_url is None
    assert settings.wazuh_indexer_password is None
    # Faz 02: mock-first varsayılan mod gerçek indexer'dır.
    assert settings.wazuh_source_mode == "indexer"
    assert settings.wazuh_index_pattern == "wazuh-alerts-*"
    assert settings.is_prod is False


def test_empty_wazuh_env_values_become_none() -> None:
    settings = Settings(**_base(wazuh_indexer_url="", wazuh_indexer_user="  "))
    assert settings.wazuh_indexer_url is None
    assert settings.wazuh_indexer_user is None


def test_invalid_indexer_url_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        Settings(**_base(wazuh_indexer_url="wazuh-indexer:9200"))
    assert "WAZUH_INDEXER_URL" in str(exc.value)


def test_prod_mode_forbids_mock_source() -> None:
    """Üretimde sahte Wazuh kaynağı sessiz telafi olurdu; yasaktır (AGENTS.md §3)."""
    with pytest.raises(ValidationError) as exc:
        Settings(**_base(app_env="prod", wazuh_source_mode="mock"))
    assert "mock" in str(exc.value)


def test_get_settings_clear_error_on_missing_config(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zorunlu config eksikse anlaşılır hata verilmeli; sessiz telafi yasak."""
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.chdir(tmp_path)  # .env dosyası bulunmayan izole dizin
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError) as exc:
            get_settings()
        message = str(exc.value)
        assert "JWT_SECRET" in message or "jwt_secret" in message
        assert ".env" in message
    finally:
        get_settings.cache_clear()


# --- Faz 04: Ollama iç ağ host kısıtı (phases/04: "Model API'si yalnızca iç
# ağ/localhost üzerinden erişilebilir olsun") ---------------------------------


class TestOllamaHostRestriction:
    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost:11434",
            "http://127.0.0.1:11434",
            "http://10.1.2.3:11434",       # RFC1918 özel
            "http://192.168.1.50:11434",   # RFC1918 özel
            "http://172.16.5.5:11434",     # RFC1918 özel
            "http://ollama:11434",          # docker servis adı (tek etiket)
            "http://host.docker.internal:11434",
            "http://ollama.internal:11434",
            "http://infer.local:11434",
            "http://[::1]:11434",           # IPv6 loopback
        ],
    )
    def test_internal_hosts_accepted(self, url: str) -> None:
        settings = Settings(**_base(ollama_base_url=url))
        assert settings.ollama_base_url == url

    @pytest.mark.parametrize(
        "url",
        [
            "http://api.example.com:11434",   # genel FQDN
            "http://8.8.8.8:11434",           # genel IP
            "http://172.32.0.1:11434",        # 172.32 RFC1918 DIŞI (genel aralık)
            "https://qwen.somedomain.org",
        ],
    )
    def test_public_hosts_rejected_by_default(self, url: str) -> None:
        with pytest.raises(ValidationError) as exc:
            Settings(**_base(ollama_base_url=url))
        assert "iç ağ" in str(exc.value)

    def test_public_host_requires_explicit_escape_hatch(self) -> None:
        """Bilinçli istisna mümkündür ama varsayılan KAPALIDIR."""
        settings = Settings(
            **_base(ollama_base_url="http://api.example.com:11434",
                    ollama_allow_public_host=True)
        )
        assert settings.ollama_allow_public_host is True

    def test_non_http_scheme_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            Settings(**_base(ollama_base_url="ftp://localhost:11434"))
        assert "http" in str(exc.value)

    def test_analysis_defaults_are_safe(self) -> None:
        """Faz 04 güvenli varsayıllar: kill switch açık ama döngü kapalı."""
        settings = Settings(**_base())
        assert settings.analysis_enabled is True
        assert settings.worker_loop_enabled is False  # arka plan döngüsü KAPALI
        assert settings.ollama_model_tag == "qwen3:4b"
        assert settings.ollama_model_quantization == "Q4_K_M"
        assert settings.ollama_allow_public_host is False
        assert settings.worker_timeout_seconds == 120.0
