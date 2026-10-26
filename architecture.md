# Önerilen Mimari

## Bileşenler
1. **Wazuh Manager/Indexer/Dashboard**: mevcut Wazuh kurulumunun resmi bileşenleri; sürüm ve dağıtım biçimi doğrulanmalı.
2. **Integration/Collector**: Wazuh alert'lerini desteklenen API/integration mekanizmasıyla alır; minimum yetkili kimlik bilgisi kullanır.
3. **Event Normalizer**: farklı alert alanlarını iç ortak modele dönüştürür, alanları maskeler, olay kimliğini ve zamanını korur.
4. **Rules/Correlation**: bilinen eşleşmeleri, eşik ve zaman pencerelerini deterministik biçimde değerlendirir.
5. **Analysis Queue/Worker**: olayları sıraya alır, tekrarları idempotent işler, Qwen çağrısını zaman aşımıyla yapar.
6. **Ollama + Qwen3 4B**: yerel model çıkarımı; model sürümü ve quantization sabitlenip ölçülür.
7. **Output Validator**: model cevabını katı JSON şemasına göre doğrular; hatalı çıktıyı reddeder.
8. **Policy Engine**: yalnızca gözlem/öneri modunda başlar; izinli aksiyonlar ve insan onayı kuralları burada uygulanır.
9. **Backend API**: auth, RBAC, olay listesi, analiz, health, audit ve yapılandırma endpoint'leri.
10. **Web UI**: genel durum, sunucular, olaylar, AI değerlendirmeleri, olay detayları, audit ve ayarlar.
11. **Database**: alert referansları, AI analizleri, kullanıcılar/roller, audit kayıtları ve ayarlar. İlk aşamada gereksiz ham log kopyalamaktan kaçın.
12. **Observability**: servis health, kuyruk uzunluğu, model latency, hata oranı, kaynak tüketimi.

## Örnek olay akışı
Wazuh alert → collector → normalizer/redaction → rule/correlation → queue → Qwen analysis → schema validation → DB → panel → (ileriki fazda) policy engine → onaylı, allowlist eylemi.

## Örnek AI analiz sözleşmesi
```json
{
  "schema_version": "1.0",
  "alert_ids": ["example-alert-id"],
  "summary": "Kısa ve kanıta dayalı açıklama",
  "assessment": "suspicious",
  "confidence": 0.72,
  "evidence": [
    {
      "field": "rule.id",
      "value": "example",
      "meaning": "Bu alan neden önemli"
    }
  ],
  "alternative_explanations": ["Meşru otomasyon olabilir"],
  "recommended_next_steps": [
    {
      "type": "collect_more_evidence",
      "reason": "Bağlantılı olayları kontrol et"
    }
  ],
  "requires_human_review": true
}
```

`assessment` için kontrollü enum önerisi: `benign`, `suspicious`, `likely_malicious`, `inconclusive`. `confidence` modelin kalibre edilmiş gerçek olasılığı değildir; test edilip kalibrasyon yapılana kadar yalnızca modelin öz değerlendirmesi olarak ele alınmalıdır. Wazuh'un orijinal severity/rule alanları değiştirilmemelidir.

## İlk sürümde yapılmaması gerekenler
- Modelin ürettiği serbest shell komutlarını çalıştırmak.
- İlk sürümde otomatik firewall/SSH ayarı değiştirmek.
- Her alarm için bütün logları modele göndermek.
- Model çıktısını doğrulamadan HTML'de render etmek.
- Wazuh API kimlik bilgilerini tarayıcıya göndermek.
- Test edilmemiş otomatik remediation'ı üretim sunucusunda açmak.
