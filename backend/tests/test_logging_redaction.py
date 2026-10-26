"""Log redaction testi (Faz 02): hassas anahtarlar loglara asla düz yazılmaz.

AGENTS.md §6: loglara parola, token, özel anahtar yazılmaz.
structlog zinciri redaction_processor ile kurulur (app/core/logging.py).

Not: structlog.testing.capture_logs() processor zincirini değiştirdiği için
redaction zincirini değiştirebilir; bu yüzden gerçek zincir LogCapture
processor'ıyla yeniden kurulur ve ucu yakalanır.
"""

from __future__ import annotations

import structlog
from structlog.testing import LogCapture

from app.core.logging import REDACTED, SENSITIVE_KEYS, redaction_processor


def _chain_with_capture() -> tuple[LogCapture, structlog.BoundLogger]:
    capture = LogCapture()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redaction_processor,
            capture,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(0),
        cache_logger_on_first_use=False,
    )
    return capture, structlog.get_logger("test.redaction")


def test_sensitive_keys_are_redacted_in_real_chain() -> None:
    capture, logger = _chain_with_capture()
    logger.info(
        "login_attempt",
        user="analist",
        password="SAHTE-PAROLA-123",  # noqa: S105, S106 — yalnızca test değeri
        wazuh_indexer_password="SAHTE-INDEXER-PAROLA",  # noqa: S105, S106 — test değeri
        nested={"token": "SAHTE-TOKEN", "ok": 1},  # noqa: S105
    )

    assert len(capture.entries) == 1
    event = capture.entries[0]
    assert event["password"] == REDACTED
    assert event["wazuh_indexer_password"] == REDACTED
    assert event["nested"]["token"] == REDACTED
    assert event["user"] == "analist"  # normal alanlar korunur
    dumped = str(event)
    assert "SAHTE-PAROLA-123" not in dumped
    assert "SAHTE-INDEXER-PAROLA" not in dumped
    assert "SAHTE-TOKEN" not in dumped


def test_redaction_processor_recursive() -> None:
    value = {"a": [{"authorization": "Bearer xyz"}], "wazuh_indexer_password": "p"}
    masked = redaction_processor(None, "info", dict(value))  # type: ignore[arg-type]
    assert masked["a"][0]["authorization"] == REDACTED
    assert masked["wazuh_indexer_password"] == REDACTED
    assert "wazuh_indexer_password" in SENSITIVE_KEYS
