# Faz 03 — Normalizasyon, redaction ve depolama

## Geliştirme promptu

Wazuh alert'lerini ortak, sürümlenmiş bir event modeline dönüştür. Orijinal alert ID'sini, kaynak zamanını, agent/server bilgisini ve orijinal rule/severity değerlerini koru. Model değerlendirmesini ayrı alanda tut.

Gereksinimler:
- UTC timestamp ve idempotency key
- Kaynak JSON'un kontrollü alan eşlemesi
- Parola, token, e-posta/IP gibi hassas alanlar için yapılandırılabilir redaction politikası; IP maskeleme ürün gereksinimine göre ayarlanabilir
- DB migration, indeksler, retention ayarı
- Tekrar gelen alert aynı olayı/analizi çoğaltmasın
- Ham logu gereksiz yere çoğaltma; saklama gerekçesini belgele
- DB hata/transaction davranışı ve erişim yetkileri
- Kullanıcı girdileri ve log metinleri güvenilmeyen veri kabul edilmeli.

## Ayrı test/doğrulama promptu

Sentetik alert fixture'larıyla normalizasyon testlerini çalıştır. Alan eksikliği, farklı timestamp biçimleri, bozuk JSON, hassas alanlar, duplicate event, aynı ID ile değişik payload, DB kesintisi ve migration rollback senaryolarını test et. Orijinal severity/rule alanlarının korunmasını, secret'ların saklanan analiz bağlamında maskelenmesini ve duplicate kayıtların kontrol edilmesini doğrula. Fixture'larda gerçek müşteri verisi bulunmamalı.
