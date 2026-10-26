---
name: secure-remediation
description: İzin listesi, insan onayı, audit ve geri dönüş planı ile sınırlı güvenlik müdahalesi tasarlamak için kullan.
---

# Secure Remediation Skill

## Varsayılan
`observe_only`. Eylemler varsayılan olarak dry-run. LLM doğrudan eylem çalıştıramaz.

## Zorunlu kontroller
- Action type enum ve allowlist
- Hedef/argüman şema doğrulaması
- Sunucu kapsamı ve yetki kontrolü
- Gerekli durumlarda ikinci kişi/onay
- Onayın kullanıcı, zaman, kapsam ve gerekçesiyle kaydı
- Rate limit, TTL, idempotency ve kill switch
- Öncesi/sonrası kanıtları ve audit kaydı
- Rollback/mitigation runbook
- Sahte executor ile otomatik test

## Yasak varsayılanlar
- LLM'nin ürettiği serbest shell komutunu çalıştırma
- Güvenlik loglarını silme veya değiştirme
- Kendi erişimini kesebilecek firewall/SSH değişikliği
- İnsan onayı olmadan kritik sistemleri durdurma
- Başka kullanıcı/sunuculara yetkisiz müdahale

Üretim eylemi tasarlanmadan önce tehdit modeli, etki alanı, geri dönüş yöntemi ve onay süreci belgelenmelidir.
