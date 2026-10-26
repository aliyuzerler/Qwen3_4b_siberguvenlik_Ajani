# Faz 01 — Proje iskeleti ve temel güvenlik

## Geliştirme promptu

Faz 00 onaylı mimarisine göre en küçük çalışabilir iskeleti oluştur. Teknoloji seçimi henüz kesinleşmediyse kodlamaya başlamadan önce seçenek ve gerekçeyi bildir.

Gereksinimler:
- Modüler backend ve frontend yapılandırması (tek repo seçildiyse anlaşılır klasörler)
- Merkezi config doğrulama; secret'lar sadece environment/secret store üzerinden
- Liveness/readiness health check
- Yapılandırılmış loglama, correlation/request ID
- Veritabanı migration altyapısı
- Unit test ve lint/test komutları
- `.env.example` sahte değerlerle; gerçek `.env` gitignore içinde
- Docker kullanılıyorsa güvenli, non-root ve pinlenmiş image/dependency yaklaşımı
- README'de yerel kurulum ve test komutları
Şimdilik Wazuh bağlantısı, LLM ve remediation ekleme. Uygulama güvenli varsayılanlarla açılmalı.

## Ayrı test/doğrulama promptu

Faz 01 testini çalıştır. Temiz kurulum adımlarını uygula; build, lint, unit test ve health endpoint'i doğrula. Zorunlu config eksikse uygulama açık ve anlaşılır hata vermeli; secret eksiklerini sahte varsayılanlarla sessizce telafi etmemeli. Git'te gerçek secret veya .env olmadığını kontrol et. Uygulamanın root/admin yetkisi gerektirmeden çalışabildiği ölçüde doğrula. Gerçek test çıktılarıyla başarılı/başarısız rapor üret.
