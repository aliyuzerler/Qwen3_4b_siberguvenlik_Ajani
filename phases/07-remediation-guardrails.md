# Faz 07 — Güvenli müdahale hazırlığı

## Geliştirme promptu

Bu fazda gerçek otomatik müdahaleyi varsayılan olarak açma. Önce dry-run policy engine ve audit akışını geliştir.

Gereksinimler:
- Başlangıç modu observe_only/dry_run
- Tipli action enum; serbest shell komutu yok
- Allowlist, hedef kapsamı, argüman doğrulama, TTL ve rate limit
- İnsan onayı ve onaylayan kullanıcı kaydı
- Eylem öncesi kanıt paketi ve risk açıklaması
- Kill switch ve rollback/mitigation runbook
- Kritik sistem erişimini kesebilecek firewall/SSH işlemlerini varsayılan olarak engelle
- Her aksiyonun sonucu ve hata durumu audit log'a yazılsın
- Model eylemi doğrudan başlatamaz; policy engine ve yetkili backend başlatır
İlk testlerde gerçek sistem değişikliği yerine fake executor kullan.

## Ayrı test/doğrulama promptu

Remediation güvenlik testleri: modelden gelen serbest komut, bilinmeyen action type, yanlış hedef, eksik onay, süresi dolmuş onay, tekrar oynatılan istek, rate limit, kill switch, audit DB hatası ve executor timeout. Tüm gerçek executor çağrılarının testte fake olduğunu doğrula. Observe-only modda sistem değişikliği yapılmadığını kanıtla. Kritik erişimi kesebilecek eylemlerin reddedildiğini doğrula. Üretim sunucusunda bu faz testini gerçek engelleme yaparak çalıştırma.
