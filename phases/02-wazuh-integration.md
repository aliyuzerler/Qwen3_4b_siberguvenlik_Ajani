# Faz 02 — Wazuh bağlantısı

## Geliştirme promptu

Wazuh entegrasyonunu ayrı adapter modülünde uygula. Önce kurulu/hedef Wazuh sürümünün resmi API dokümantasyonunu ve kimlik doğrulama yöntemini doğrula; endpoint, alan veya sürüm davranışı uydurma.

Gereksinimler:
- En az ayrıcalıklı, mümkünse salt okunur servis hesabı
- Secret'lar backend'de; browser/frontend'e geçmez
- Timeout, sınırlı retry/backoff, circuit breaker ve anlaşılır hata durumları
- Alert listesi ve alert detayı için tipli iç arayüz
- Pagination/time-window desteği ve oran sınırlamasına saygı
- Testlerde mock Wazuh API; staging için gerçek bağlantı talimatı
- Bağlantı durumu ve son başarılı senkronizasyon bilgisi
- API cevabından yalnızca gereken alanları al
Otomatik müdahale veya Wazuh konfigürasyonu değiştirme özelliği ekleme.

## Ayrı test/doğrulama promptu

Wazuh adapter testlerini çalıştır. Başarılı yanıt, boş liste, sayfalama, 401/403, 429, 5xx, timeout, bozuk JSON ve bağlantı kesilmesini simüle et. Token/logların test çıktısına yazılmadığını kontrol et. Yetkisiz bir endpoint veya yazma işlemi çağrılmadığını doğrula. Alert ID, zaman damgası ve orijinal rule/severity alanlarının kaybolmadığını kontrol et. Gerçek Wazuh testi varsa yalnızca staging ve salt okunur kimlikle çalıştır.
