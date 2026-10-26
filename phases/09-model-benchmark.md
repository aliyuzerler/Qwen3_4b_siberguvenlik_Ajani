# Faz 09 — Model benchmark ve fine-tuning kararı

## Geliştirme promptu

Qwen3 4B için sabit, etiketli bir değerlendirme kümesi oluşturma ve çalıştırma altyapısı kur. Veri yetkili/sentetik veya lisansı uygun kaynaklardan gelmeli; hassas veriler temizlenmeli.

Ölçümler:
- Alert classification precision/recall/F1
- False-positive rate
- JSON schema-valid rate
- Evidence correctness (kanıtın kaynak alert alanıyla eşleşmesi)
- Unsupported claim rate
- p50/p95 latency ve bellek kullanımı
- Benign bakım aktivitelerinde yanlış alarm
- Prompt injection dayanıklılığı

Baseline: yalnızca Wazuh kuralları, prompt-only Qwen ve kural+korelasyon+Qwen karşılaştırması. Eğitim/validation/test setlerini olay ailesi veya zaman bazında ayır; aynı veya çok benzer olayları farklı split'lere sızdırma. Fine-tuning önerisini yalnızca sonuçlarla gerekçelendir.

## Ayrı test/doğrulama promptu

Benchmark'ı sabit sürümde çalıştır ve sonuçları CSV/JSON olarak kaydet. Seed, model tag/quantization, prompt sürümü, dataset sürümü ve donanımı raporla. Precision, recall, F1, FPR, schema-valid rate, unsupported-claim rate, p50/p95 latency değerlerini hesapla. Fine-tuning öncesi baseline oluştur. Etiketler eksik veya veri sızıntısı varsa sonucu geçerli ilan etme.
