"""Merkezi uygulama yapılandırması (Faz 01).

Kurallar (AGENTS.md §3, §4):
- Secret'lar yalnızca environment / secret store üzerinden gelir.
- Zorunlu alan eksikse uygulama açık ve anlaşılır hata ile başlamayı reddeder;
  sahte varsayılanlarla sessiz telafi yapılmaz.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlparse

from pydantic import Field, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Tek kaynak: analiz şema sözleşmesi services.analysis.models içinde tanımlıdır;
# config'e ekstra summary limiti kopyası ALINMADI (num_predict + şema sabiti yeterli).

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

    # --- JWT (Faz 05: panel auth) ---
    jwt_algorithm: str = "HS256"
    jwt_access_ttl_minutes: int = Field(default=15, ge=1, le=120)
    jwt_refresh_ttl_minutes: int = Field(default=1440, ge=5, le=60 * 24 * 7)

    # --- Panel auth (Faz 05) ---
    # İlk kurulumda users tablosu boşsa 'admin' kullanıcısı BU parolayla
    # oluşturulur (bootstrap). Parola ASLA log/yanıta yansıtılmaz; kullanıcı
    # oluşturulduktan sonra bu değer yok sayılır. Boş bırakılırsa hiçbir
    # kullanıcı otomatik oluşturulmaz (uyarı loglanır; panel girişi kapalı olur).
    admin_bootstrap_password: str | None = None
    admin_bootstrap_username: str = "admin"
    # Giriş/refresh uçlarına IP başına dakikalık istek tavanı (brute-force
    # freni). Uygulama bellek içi sayaçtır; çok prosessli dağıtımda Faz 08'de
    # paylaşımlı depoya taşınacaktır.
    auth_rate_limit_per_minute: int = Field(default=10, ge=1, le=600)

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
    # Kullanıcı makinesindeki yerel Ollama; model tag sabittir (Faz 00 kararı:
    # qwen3:4b, CPU modu, Q4_K_M quantization önerisi).
    ollama_base_url: str = "http://localhost:11434"
    ollama_model_tag: str = "qwen3:4b"
    ollama_model_quantization: str = "Q4_K_M"
    ollama_temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    ollama_num_predict: int = Field(default=512, ge=32, le=4096)
    # "Model API'si yalnızca iç ağ/localhost üzerinden erişilebilir olsun":
    # false iken yalnızca loopback/özel IP/tek-etiket hostname/host.docker.internal
    # kabul edilir; gerçek genel FQDN/IP için bilinçli açma gerekir (test/dev).
    ollama_allow_public_host: bool = False

    # --- Analiz worker'ı (Faz 04) ---
    # Kill switch: false iken analiz devre dışı (/ready "disabled" raporlar).
    analysis_enabled: bool = True
    analysis_batch_size: int = Field(default=10, ge=1, le=100)
    analysis_max_retries: int = Field(default=1, ge=0, le=5)
    analysis_backoff_base_seconds: float = Field(default=1.0, gt=0, le=30)
    analysis_max_context_chars: int = Field(default=4000, ge=256, le=32_000)
    analysis_max_output_chars: int = Field(default=6000, ge=1000, le=64_000)
    worker_concurrency: int = Field(default=2, ge=1, le=16)
    worker_timeout_seconds: float = Field(default=120.0, gt=0, le=600)
    # Birleşik arka plan döngüsü (fetch → store → analyze): VARSAYILAN KAPALI.
    worker_loop_enabled: bool = False
    worker_interval_seconds: float = Field(default=30.0, ge=5.0, le=3600.0)
    worker_initial_window_seconds: float = Field(default=900.0, ge=10.0, le=86_400.0)

    # --- Korelasyon (Faz 06) ---
    # Kill switch: false iken korelasyon döngüsü hiç çalışmaz (kural tespiti
    # yapılmaz; mevcut tespit kayıtları panel/API'de okunmaya devam eder).
    correlation_enabled: bool = True
    # Motor her turda bu geriye dönük pencereyi tarar (worker interval ile
    # birlikte). Pencere, en uzun kural penceresinden büyük olmalıdır ki
    # süren olaylar tur atlamadan yakalansın.
    correlation_lookback_seconds: float = Field(default=21_600.0, ge=60.0, le=172_800.0)
    # Tek turda taranacak en fazla event sayısı (bellek/tanımlanabilirlik tavanı).
    correlation_max_events_per_run: int = Field(default=5_000, ge=100, le=100_000)

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

    @field_validator("ollama_base_url")
    @classmethod
    def _validate_ollama_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError(
                "OLLAMA_BASE_URL 'http://' veya 'https://' ile başlamalıdır "
                "(örnek: http://localhost:11434)."
            )
        return value

    @model_validator(mode="after")
    def _validate_ollama_host(self) -> Settings:
        """Model API yalnızca iç ağdan erişilir (phases/04).

        İzinli: loopback (localhost/127.x/::1), özel IP (RFC1918/uydu aralıkları),
        tek-etiket hostname (docker servis adı, örn. 'ollama'), host.docker.internal,
        *.internal / *.local. Genel FQDN/IP ancak ollama_allow_public_host=true
        ile açılır (bilinçli istisna; mesajda gerekçe).
        """
        if self.ollama_allow_public_host:
            return self
        host = urlparse(self.ollama_base_url).hostname
        if host is None:
            raise ValueError(
                "OLLAMA_BASE_URL içinde geçerli bir host bulunamadı."
            )
        lowered = host.lower()
        if lowered in {"localhost", "host.docker.internal"}:
            return self
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            if ip.is_loopback or ip.is_private:
                return self
        else:
            # Tek-etiket (docker servis adı) veya iç ağ etiketli FQDN
            if "." not in lowered or lowered.endswith((".internal", ".local")):
                return self
        raise ValueError(
            f"OLLAMA_BASE_URL genel/şüpheli bir host'a işaret ediyor ('{host}'). "
            "Model API yalnızca iç ağ/localhost üzerinden erişilebilir. Gerçekten "
            "genel bir uç nokta gerekiyorsa OLLAMA_ALLOW_PUBLIC_HOST=true yapın "
            "(olay verisi dışarı çıkabilir; üretimde önerilmez)."
        )

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
