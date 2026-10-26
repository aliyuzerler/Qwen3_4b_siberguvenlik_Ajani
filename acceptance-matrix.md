# Faz Kabul Matrisi

| Faz | Kabul ölçütü |
|---|---|
| 00 Keşif | Teknoloji, sürüm, mevcut repo, veri akışı, tehdit modeli ve belirsizlikler belgeli; kod değişikliği yok |
| 01 İskelet | Temiz kurulum/derleme, health endpoint, config validation, secret'lar repoda değil |
| 02 Wazuh bağlantısı | Salt okunur bağlantı, timeout, hata yönetimi, alert örneği ve sözleşme testleri |
| 03 Normalizasyon | Zaman/ID korunur, hassas alanlar maskelenir, idempotency testi geçer |
| 04 Qwen analizi | Ollama bağlantısı, katı şema, timeout, invalid JSON fallback, prompt injection testleri |
| 05 Panel | Auth/RBAC, olay listesi/detayı, filtreler, AI değerlendirmesi, hata/boş/loading durumları |
| 06 Korelasyon | Zaman pencereleri, tekrarlar, kanıt bağlantıları ve sentetik senaryo testleri |
| 07 Müdahale güvenliği | Başlangıçta dry-run; allowlist; insan onayı; audit; timeout; rollback/kill switch |
| 08 Güvenlik testi | Yetkisiz erişim, injection, rate limit, secret scanning, dependency scan ve backup/restore testleri |
| 09 Model değerlendirme | Sabit holdout seti, baseline karşılaştırması, precision/recall/FPR/latency/JSON-valid ölçümleri |
| 10 Fine-tuning (opsiyonel) | Veri lisansları kontrol edilmiş, split leakage yok, önce/sonra metrikleri iyileşmiş, model geri alınabilir |
| 11 Dağıtım | Staging doğrulaması, backup, monitoring, rollback planı, dokümantasyon ve runbook |
