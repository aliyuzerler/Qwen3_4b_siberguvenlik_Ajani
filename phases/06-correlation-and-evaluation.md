# Faz 06 — Korelasyon ve değerlendirme

## Geliştirme promptu

Kural tabanlı korelasyon katmanı ekle. LLM'yi tek başına olay ilişkilendirme kaynağı yapma.

Gereksinimler:
- Yapılandırılabilir zaman pencereleri ve kurallar
- Ortak agent, IP, kullanıcı, süreç ve alert ID gibi mevcut kanıt alanlarıyla ilişki
- Her korelasyon için hangi olayların ve hangi kuralın eşleştiğini göster
- Duplicate/near-duplicate yönetimi
- Kural sürümü ve audit kaydı
- Sentetik, etiketlenmiş test senaryoları
- Kural çıktısı ve LLM yorumu ayrı tutulmalı
İlk etapta bilinen örnek senaryolar için basit ve açıklanabilir kurallarla başla; gereksiz ML/anomali algoritması ekleme.

## Ayrı test/doğrulama promptu

Etiketli sentetik senaryolarla korelasyon motorunu test et: normal bakım, başarısız login burst, başarılı login sonrası şüpheli değişiklik, duplicate event, farklı sunuculardaki benzer olay, zaman sırası bozuk olay ve eksik alan. Precision/recall, false-positive rate ve event-to-alert latency hesapla. Her eşleşmede kanıt ve kural ID'si gösteriliyor mu doğrula. Gerçek saldırı verisi gibi sunulan sentetik kayıtlar açıkça etiketlenmeli.
