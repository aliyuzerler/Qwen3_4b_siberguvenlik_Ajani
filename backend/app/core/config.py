"""Merkezi uygulama yapılandırması (Faz 01).

Kurallar (AGENTS.md §3, §4):
- Secret'lar yalnızca environment / secret store üzerinden gelir.
- Zorunlu alan eksikse uygulama açık ve anlaşılır hata ile başlamayı reddeder;
  sahte varsayılanlarla sessiz telafi yapılmaz.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, Literal

from pydantic import Field, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

if TYPE_CHECKING:
    from app.services.normalization.redaction import RedactionPolicy


class Settings(BaseSettings):
    """Tip güvenli, doğrulanmış uygulama ayarları."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Uygulama ---
    app_name: str = "ajant-backend"
    app_env: Literal["dev", "staging", "prod"] = "dev"
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    api_prefix: str = "/api/v1"
    cors_origins: str = "http://localhost:3000"

    # --- Zorunlu gizli alanlar (sahte varsayılan YOK) ---
    jwt_secret: str = Field(min_length=32)
    database_url: str

    # --- JWT (Faz 05'te kullanılacak) ---
    jwt_algorithm: str = "HS256"
    jwt_access_ttl_minutes: int = Field(default=15, ge=1, le=120)
    jwt_refresh_ttl_minutes: int = Field(default=1440, ge=5, le=60 * 24 * 7)

    # --- Wazuh Indexer (Faz 02) — alert kaynağı; doldurulana kadar devre dışı ---
    # Kanıt: Wazuh Server API'de (55000) alert OKUMA endpoint'i yoktur (resmi spec'te
    # yalnızca POST /events ingest vardır). Alert'ler Indexer API'den (9200)
    # wazuh-alerts-* indeksinden salt okunur okunur. Ayrıntı: docs/wazuh-staging.md
    wazuh_source_mode: Literal["indexer", "mock"] = "indexer"
    wazuh_indexer_url: str | None = None
    wazuh_indexer_user: str | None = None
    wazuh_indexer_password: str | None = None
    wazuh_index_pattern: str = "wazuh-alerts-*"
    wazuh_verify_tls: bool = True
    wazuh_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    wazuh_page_size: int = Field(default=100, ge=1, le=1000)
    wazuh_max_retries: int = Field(default=2, ge=0, le=5)
    wazuh_backoff_base_seconds: float = Field(default=0.5, gt=0, le=30)
    wazuh_breaker_failure_threshold: int = Field(default=5, ge=1, le=50)
    wazuh_breaker_reset_seconds: float = Field(default=30.0, gt=0, le=600)

    # --- Normalizasyon / redaction (Faz 03) ---
    # Saklanan analiz bağlamında hassas alanlar maskeleme politikası.
    # IP maskeleme ürün gereksinimine göre ayarlanabilir (phases/03:
    # "IP maskeleme ürün gereksinimine göre ayarlanabilir"):
    #   none     → IP değeri olduğu gibi saklanır (analitik değer tam)
    #   masked   → host bitleri sıfırlanır (IPv4 /24, IPv6 /64) — alt ağ korunur
    #   redacted → değer tamamen maske ("[ip]") ile değiştirilir
    redaction_enabled: bool = True
    redact_ip_mode: Literal["none", "masked", "redacted"] = "masked"
    redact_email_mode: Literal["none", "masked"] = "masked"
    redact_secret_patterns: bool = True
    # Ham alert JSONB saklama (varsayılan KAPALI): normalizasyon alanları analiz için
    # yeterlidir; ham kopya gerekçesiyle çoğaltılmaz (gerekçe: docs/phase-03-verification.md).
    store_raw_alert: bool = False

    # --- Retention (Faz 03) — AGENTS.md §6: saklama süresi yapılandırılabilir ---
    retention_days: int = Field(default=30, ge=1, le=365)

    # --- Ollama / Model (Faz 04) ---
    ollama_base_url: str = "http://localhost:11434"
    ollama_model_tag: str = "qwen3:4b"
    worker_concurrency: int = Field(default=2, ge=1, le=16)
    worker_timeout_seconds: float = Field(default=120.0, gt=0, le=600)

    # --- Politika (Faz 07) ---
    policy_mode: Literal["observe_only", "dry_run"] = "observe_only"

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, value: str) -> str:
        allowed = ("postgresql+asyncpg://", "sqlite+aiosqlite:///")
        if not value.startswith(allowed):
            raise ValueError(
                "DATABASE_URL 'postgresql+asyncpg://' veya 'sqlite+aiosqlite:///' ile "
                "başlamalıdır (async SQLAlchemy sürücüsü zorunludur)."
            )
        return value

    @field_validator(
        "wazuh_indexer_url", "wazuh_indexer_user", "wazuh_indexer_password", mode="before"
    )
    @classmethod
    def _empty_string_to_none(cls, value: object) -> object:
        """Boş env değerleri (örn. WAZUH_INDEXER_URL=) None sayılır."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("wazuh_indexer_url")
    @classmethod
    def _validate_indexer_url(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith(("http://", "https://")):
            raise ValueError(
                "WAZUH_INDEXER_URL 'http://' veya 'https://' ile başlamalıdır "
                "(örnek: https://wazuh-indexer:9200)."
            )
        return value

    @model_validator(mode="after")
    def _validate_wazuh_mode(self) -> Settings:
        """Üretimde sahte/mock Wazuh kaynağı yasaktır (sessiz telafi yok, AGENTS.md §3)."""
        if self.app_env == "prod" and self.wazuh_source_mode == "mock":
            raise ValueError(
                "APP_ENV=prod iken WAZUH_SOURCE_MODE=mock kullanılamaz: üretimde "
                "alert kaynağı gerçek Wazuh Indexer olmalıdır."
            )
        return self

    @property
    def redaction_policy(self) -> RedactionPolicy:
        """Ayarlardan redaction politikası üretir (normalizasyon paketi türü)."""
        # Lazy import: config → services dairesel bağımlılığı önler.
        from app.services.normalization.redaction import RedactionPolicy

        return RedactionPolicy(
            enabled=self.redaction_enabled,
            ip_mode=self.redact_ip_mode,
            email_mode=self.redact_email_mode,
            secret_patterns=self.redact_secret_patterns,
        )

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def is_prod(self) -> bool:
        return self.app_env == "prod"


@lru_cache
def get_settings() -> Settings:
    """Ayarları yükler; zorunlu alan eksikse anlaşılır hata ile reddeder."""
    try:
        return Settings()  # type: ignore[call-arg]  # değerler env/.env üzerinden okunur
    except ValidationError as exc:
        missing: list[str] = []
        for error in exc.errors():
            loc = error.get("loc")
            missing.append(str(loc[0]) if loc else "bilinmeyen-alan")
        raise RuntimeError(
            "Yapılandırma doğrulaması başarısız. Eksik/geçersiz alanlar: "
            + ", ".join(missing)
            + ". Çözüm: 'backend/.env.example' dosyasını 'backend/.env' olarak kopyalayın ve "
            "zorunlu alanları (JWT_SECRET, DATABASE_URL) gerçek değerlerle doldurun. "
            "Güvenlik gereği sahte varsayılanlarla sessiz telafi yapılmaz."
        ) from exc
