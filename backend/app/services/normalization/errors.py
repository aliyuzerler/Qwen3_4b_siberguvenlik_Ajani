"""Normalizasyon ve depolama hata hiyerarşisi (Faz 03).

Kurallar (AGENTS.md §4, §7 — Faz 02 errors.py ile aynı disiplin):
- Hata mesajları anlaşılır ve Türkçedir; credential/token ASLA içermez.
- Hata mesajları güvenilmeyen alert verisini ham haliyle TAŞIMAZ
  (yalnızca alan adı ve uzunluk gibi yapısal bilgi içerir).
- Retry edilebilirlik hatanın türünden okunur (retryable özelliği).
"""

from __future__ import annotations


class NormalizationError(Exception):
    """Alert ortak event modeline dönüştürülemedi (eksik/geçersiz zorunlu alan).

    Retry anlamsızdır: veri bozuktur, kaynak yanıtının değişmesi gerekir.
    """

    retryable: bool = False

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class StorageError(Exception):
    """Depolama katmanı hatası (bağlantı, transaction, kısıt ihlali vb.).

    retryable=True  → geçici altyapı hatası (bağlantı kopması, DB kapalı):
                      aynı veri tekrar denendiğinde idempotency key sayesinde
                      güvenle yeniden yazılabilir.
    retryable=False → kalıcı veri/kısıt hatası: yeniden denemek sonucu değiştirmez.
    """

    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.message = message
        self.retryable = retryable
