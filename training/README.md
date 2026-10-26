# Qwen3 4B — Fine-tuning karar ve geliştirme planı

## Ön karar
Fine-tuning ilk adım değildir. Önce Qwen3 4B base/instruct modelini sabit bir prompt, JSON schema validation, redaction, Wazuh kuralları ve retrieval/korelasyon ile ölç. Fine-tuning, yalnızca ölçülebilir ve tekrar eden bir hata sınıfı kaldıysa düşünülmelidir.

## Faz T1 — Veri gereksinimi
- Görevleri ayır: alert triage, açıklama, sınıflandırma, JSON üretimi, aksiyon önerisi.
- Başarı ölçütlerini önceden belirle.
- Mevcut hatalardan etiketli örnekler topla; gerçek olayların kullanım yetkisini ve lisansını doğrula.
- Parola/token/PII ve müşteri sırlarını kaldır veya maskele.
- Etiketleme rehberi hazırla; en azından kritik örnekleri ikinci kişiyle gözden geçir.

## Faz T2 — Dataset tasarımı
Önerilen her kayıt:
- `example_id`
- `task`
- `input_alert_context` (redacted, sınırlı boyut)
- `expected_output` (hedef JSON)
- `labels`: assessment, evidence correctness, benign/malicious/uncertain
- `source`, `license`, `review_status`
- `split_group` (aynı saldırı/olay ailesinin split'ler arasında sızmasını önlemek için)

Train/validation/test'i rastgele satır bölmek yerine olay ailesi, zaman aralığı veya kaynak host grubu bazında ayır. Test setini eğitimde veya prompt tuning'de kullanma. Yalnızca sentetik veri kullanılıyorsa bunu raporda açıkça belirt.

## Faz T3 — Baseline
Aynı sabit holdout setinde ölç:
1. Wazuh rule-only
2. Qwen prompt-only
3. Wazuh + deterministic correlation + Qwen
Metrikler: precision, recall, F1, false-positive rate, JSON-valid rate, evidence correctness, unsupported-claim rate, p50/p95 latency, peak RAM/VRAM.

## Faz T4 — Fine-tuning deneyi
- Önce küçük bir LoRA/QLoRA deneyi planla; kullanılan Qwen3 4B sürümünün lisansı ve teknik eğitim gereksinimlerini doğrula.
- Model ailesiyle uyumlu tokenizer/chat template kullan.
- Öğrenme oranı, epoch, sequence length, quantization ve donanımı kaydet.
- Küçük pilot çalıştır; eğitim loss'u tek başına başarı sayma.
- Checkpoint'leri ayrı sakla; orijinal modelin üstüne yazma.
- Eğitim sırasında veri sızıntısı ve hassas veri memorization riskini değerlendir.

## Faz T5 — Değerlendirme
Fine-tuned modeli aynı holdout setinde baseline ile karşılaştır. Kritik sınıflarda recall düşmesi, yanlış pozitif artması, kanıtsız iddia artması veya JSON geçerliliği düşmesi halinde yayınlama. Test setini değiştirmeden tekrar ölç.

## Faz T6 — Staging ve rollback
- Modeli üretim yerine staging'e yükle.
- Model hash'i, quantization, tokenizer/template ve eval raporunu versiyonla.
- Shadow mode çalıştır; kararları gerçek müdahaleye bağlama.
- Canlı performans baseline'ı karşılamıyorsa önceki model sürümüne dön.
- Fine-tuning modelin Wazuh kurallarının yerine geçmediğini belgele.

## Veri güvenliği
- Yetkisiz veya lisansı belirsiz logları kullanma.
- Secrets/credentials model eğitim verisine girmemeli.
- Veri saklama ve silme politikalarını uygula.
- Model çıktısının kesin saldırı kanıtı olmadığı kuralını koru.
