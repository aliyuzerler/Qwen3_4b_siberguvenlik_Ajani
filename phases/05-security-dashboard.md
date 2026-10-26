# Faz 05 — Güvenlik paneli

## Geliştirme promptu

Wazuh olaylarını ve Qwen analizlerini gösteren güvenlik panelini oluştur. Önce onaylı frontend/backend teknolojisine uy.

Ekranlar:
1. Genel bakış: agent/server sağlık durumu, açık uyarılar, son olaylar, model health
2. Olay listesi: zaman, kaynak, rule, orijinal severity, AI assessment, durum; filtreleme ve sayfalama
3. Olay detayı: orijinal kanıtlar, AI özeti, alternatif açıklamalar, ilişkili alert'ler, önerilen sonraki adımlar
4. Sunucular/agent'lar: son görülme, bağlantı/health durumu
5. Audit log
6. Ayarlar: model endpoint/tag, retention ve bildirim ayarları; hassas secret değerlerini tekrar gösterme

Güvenlik:
- Auth, RBAC ve server-side authorization
- API anahtarlarını frontend'e gönderme
- XSS'e karşı güvenli render; model/log metinlerini HTML olarak çalıştırma
- Pagination, rate limit, input validation
- Loading/empty/error states ve erişilebilirlik
- AI değerlendirmesini Wazuh'un orijinal alanlarından görsel olarak ayır
- İlk sürümde remediation butonu gösterme veya disabled/roadmap olarak işaretle.

## Ayrı test/doğrulama promptu

Panel testleri: oturum açma/kapama, rol izinleri, yetkisiz API çağrıları, olay listeleme/filtreleme/sayfalama, olay detayı, boş/hata/loading durumları, XSS payload'ı içeren log ve AI çıktısı, CSRF (uygunsa), rate limit ve secret'ın tarayıcı network/loglarına sızmaması. Kullanıcı bir alert'i görme yetkisine sahip değilse doğrudan ID ile de alamamalı. Görsel snapshot'lara ek olarak işlevsel testleri çalıştır. Test sonucu ve bilinen UI sorunlarını raporla.
