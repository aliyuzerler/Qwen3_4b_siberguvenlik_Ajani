"""Korelasyon paketi hata türleri (Faz 06).

Faz 03/04 kalıbıyla uyumlu: DB altyapı hataları StorageError(retryable)
olarak sınıflandırılır (normalization.errors) → worker döngüsü fail-fast
yapar, aynı pencere güvenle yeniden taranabilir (dedup_key idempotency
sayesinde tekrar tespit yeni satır üretmez, hit_count artar).

Korelasyon motoru saf (pure) fonksiyondur; kendi hata türü üretmez —
kural tanımı doğrulaması Pydantic ile başlangıçta yapılır.
"""

from __future__ import annotations

from app.services.normalization.errors import StorageError

__all__ = ["StorageError"]
