# Faz 08 — Güvenlik sertleştirme ve dağıtım

## Geliştirme promptu

Uygulamayı staging dağıtımına hazırla. Secret management, TLS, firewall, minimum servis yetkileri, dependency pinning, backup/restore, retention, monitoring ve incident runbook'u tamamla.

Gereksinimler:
- Non-root servisler; mümkünse servisler arası ağ segmentasyonu
- Ollama endpoint'ini internete açık bırakmama
- Wazuh API'yi yalnızca gerekli ağlardan erişilebilir tutma
- TLS ve güvenli cookie/header ayarları
- RBAC ve audit
- DB backup/restore testi
- Health check, log rotation, disk dolması alarmı
- Rate limit ve DoS dayanıklılığı
- Kurulum/upgrade/rollback dokümantasyonu
- Üretime geçişte observe-only varsayılanı

## Ayrı test/doğrulama promptu

Staging hardening testleri: port taraması yalnızca yetkili staging üzerinde, TLS/sertifika doğrulama, dışarıdan Ollama/Wazuh API erişim kontrolü, secret scanning, dependency vulnerability scan, RBAC, brute-force rate limit, backup/restore, disk dolması simülasyonu ve rollback. Her test için komut, beklenen sonuç ve gerçek sonuç raporla. Gerçek üretim verisi/secret kullanma.
