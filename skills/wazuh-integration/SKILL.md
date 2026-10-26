---
name: wazuh-integration
description: Wazuh API/alert akışını sürüm doğrulaması, minimum ayrıcalık ve dayanıklı hata yönetimiyle entegre etmek için kullan.
---

# Wazuh Integration Skill

1. Kurulu Wazuh sürümünü ve resmi dokümantasyonu doğrula; endpoint/alan uydurma.
2. Ayrı, minimum yetkili ve mümkünse salt okunur servis hesabı kullan.
3. Kimlik bilgilerini yalnızca backend secret store/environment üzerinden oku.
4. Timeout, sınırlı retry/backoff, rate limit ve circuit breaker uygula.
5. Pagination ve zaman aralığı sınırlarını uygula.
6. Alert ID, timestamp, agent, rule ve orijinal severity alanlarını koru.
7. Dış API yanıtlarını tipli modele dönüştür; doğrulanmamış alanlara güvenme.
8. Testlerde mock API kullan; gerçek entegrasyon testini staging'de yap.
9. Wazuh konfigürasyonu değiştirme veya remediation yürütme yetkisini bu adapter'a verme.
10. Secret ve kişisel verileri loglama.
