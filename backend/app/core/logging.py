"""Yapılandırılmış loglama (structlog) kurulumu.

- Tüm loglar JSON olarak üretilir; correlation/request ID içerir (AGENTS.md §6).
- Hassas anahtarlar loglanmadan önce maskelenir (redaction).
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from structlog.typing import EventDict

# Loglarda asla düz metin olarak görünmemesi gereken anahtarlar
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "token",
        "secret",
        "authorization",
        "api_key",
        "cookie",
        "set-cookie",
        "jwt_secret",
        "wazuh_indexer_password",
    }
)

REDACTED = "***REDACTED***"


def _redact(value: Any) -> Any:
    """Sözlük/liste yapısında hassas alanları özyinelemeli maskeler."""
    if isinstance(value, dict):
        return {
            str(key): (REDACTED if str(key).lower() in SENSITIVE_KEYS else _redact(val))
            for key, val in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


def redaction_processor(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """structlog processor: olay sözlüğündeki hassas alanları maskeler."""
    return _redact(event_dict)  # type: ignore[return-value]


def configure_logging(log_level: str = "INFO") -> None:
    """structlog'u JSON çıktısıyla yapılandırır."""
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            redaction_processor,
            structlog.processors.JSONRenderer(ensure_ascii=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str) -> Any:
    """İsimli structlog logger döndürür."""
    return structlog.get_logger(name)
