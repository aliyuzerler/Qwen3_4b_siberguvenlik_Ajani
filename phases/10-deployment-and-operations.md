# Faz 10 — Dağıtım ve operasyon

## Geliştirme promptu

Staging'de doğrulanan sürüm için dağıtım belgeleri ve operasyon runbook'u hazırla.

İçerik:
- Ön koşullar ve sürüm sabitleme
- Secret/env kurulumu
- Database migration ve backup
- Wazuh bağlantı kurulumu
- Ollama ve modelin yerel indirilmesi/doğrulanması
- Health check ve smoke test
- Log/metric izleme ve alarm eşikleri
- Model veya Wazuh erişimi kesilirse güvenli davranış
- Upgrade ve rollback
- Incident response ve bakım adımları
Üretim ortamına otomatik dağıtım yapma; önce staging ve kullanıcı onayı gerekir.

## Ayrı test/doğrulama promptu

Temiz staging ortamında runbook'u başka bir operatörün izleyebileceği şekilde baştan uygula. Kurulum, health, test alert, AI analysis, panel login, backup/restore ve rollback adımlarını doğrula. Model/Ollama kapalıyken sistemin güvenli fallback verdiğini kontrol et. Dokümantasyonda olmayan gizli manuel adım varsa runbook'u düzelt.
