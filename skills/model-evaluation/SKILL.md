---
name: model-evaluation
description: Yerel güvenlik LLM'sini etiketli veride ölçmek ve fine-tuning kararını kanıta dayandırmak için kullan.
---

# Model Evaluation Skill

1. Model tag'i, quantization, prompt sürümü, donanım ve dataset sürümünü sabitle.
2. Veri kaynağı/lisansı ve hassas veri temizliğini kaydet.
3. Eğitim/validation/test ayrımını olay ailesi veya zaman üzerinden yap; duplicate/leakage kontrolü uygula.
4. Wazuh-only, prompt-only LLM ve rule+LLM varyantlarını karşılaştır.
5. Precision, recall, F1, FPR, schema-valid rate, evidence correctness, unsupported-claim rate, latency ve memory ölç.
6. Benign bakım, eksik log, prompt injection ve model/servis kesintisi senaryoları ekle.
7. Fine-tuning yalnızca ölçülebilir hata türü belirlenmiş ve baseline kurulmuşsa öner.
8. Test setini prompt geliştirme/eğitim için kullanma.
9. Önce/sonra karşılaştırması yap; kritik metrik kötüleşirse modeli yayınlama.
10. Model artifact'ini, lisansını, hash'ini, eval raporunu ve rollback yolunu kaydet.
