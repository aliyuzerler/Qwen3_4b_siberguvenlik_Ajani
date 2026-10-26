"""Wazuh adapter tipli hata hiyerarşisi (Faz 02).

Kurallar (phases/02-wazuh-integration.md, AGENTS.md §4):
- Hata mesajları anlaşılır ve Türkçedir; credential/token ASLA içermez.
- Retry edilebilirlik hatanın türünden okunur (retryable özelliği).
"""

from __future__ import annotations


class WazuhError(Exception):
    """Tüm Wazuh adapter hatalarının tabanı."""

    retryable: bool = False

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class WazuhNotConfiguredError(WazuhError):
    """Wazuh kaynağı yapılandırılmamışken çağrıldı."""

    retryable = False


class WazuhAuthError(WazuhError):
    """Kimlik doğrulama/yetki hatası (HTTP 401/403). Tekrar denemesiz."""

    retryable = False


class WazuhRateLimitedError(WazuhError):
    """Oran sınırı (HTTP 429). Retry-After bilgisiyle tekrar denenebilir."""

    retryable = True

    def __init__(self, message: str, retry_after_seconds: float | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class WazuhUnavailableError(WazuhError):
    """Servis erişilemez: 5xx, zaman aşımı, bağlantı kopması, açık devre kesici."""

    retryable = True


class WazuhBadPayloadError(WazuhError):
    """Beklenmeyen/bozuk yanıt gövdesi. Yeniden denemek sonucu değiştirmez."""

    retryable = False
