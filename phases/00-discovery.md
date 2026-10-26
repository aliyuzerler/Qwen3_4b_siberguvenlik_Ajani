# Faz 00 — Keşif ve tasarım

## Geliştirme promptu

Görev: Önce mevcut depo ve çalışma ortamını incele; henüz dosya değiştirme.

AGENTS.md ve architecture.md kurallarına uy. Mevcut kod tabanı varsa framework, dil, paket yöneticisi, testler, container yapılandırması ve CI/CD dosyalarını incele. Yoksa proje sahibine teknoloji yığını seçimi için gerekçeli seçenekler sun; mevcut olmayan bir özelliğin var olduğunu varsayma.

Ürün gereksinimleri:
- Wazuh alarm/olaylarını güvenli biçimde alma
- Qwen3 4B'yi Ollama üzerinden yerel çağırma
- Olay normalizasyonu, redaction, korelasyon ve analiz geçmişi
- Güvenlik paneli, kullanıcı/rol yönetimi ve audit log
- İlk sürüm observe-only; otomatik müdahale kapalı
- İleride ölçüme dayalı opsiyonel fine-tuning

Teslim et:
1. Repo/env envanteri
2. Bağlam ve veri akışı diyagramı
3. Önerilen teknoloji yığını ve gerekçesi
4. Tehdit modeli ve güven sınırları
5. API/veri sözleşmesi taslağı
6. Test stratejisi
7. Açık sorular ve riskler
8. Fazlara bölünmüş görev listesi

Kod veya config değiştirme. Belirsiz varsayımları açıkça belirt.

## Ayrı test/doğrulama promptu

Faz 00 doğrulama görevi: Analiz raporunu bağımsız gözden geçir. Kodun değişmediğini git diff/status ile doğrula. Wazuh, Ollama, model, UI framework, veritabanı, auth ve deployment seçimleri için doğrulanmış bilgi ile varsayımı ayır. En az şu riskleri kontrol et: modelin komut çalıştırması, prompt injection içeren loglar, sırların açığa çıkması, yetki ayrımı, yanlış pozitif, Wazuh/Ollama kesintisi, tenant izolasyonu (varsa), yedek/rollback. Eksik olanları listele; bu fazın başarılı olması için kod değişikliği bulunmamalı.
