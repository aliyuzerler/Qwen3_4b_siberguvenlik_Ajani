# Genel faz test promptu şablonu

Faz [NUMARA] için AGENTS.md ve faz dokümanındaki kabul ölçütlerine göre bağımsız doğrulama yap.

- Önce test planını çıkar.
- Gerçekten çalıştırabildiğin testleri çalıştır; çalıştıramadıklarını açıkça ayır.
- Her test için beklenen sonuç ve gerçek sonucu yaz.
- Olumlu testlerin yanında negatif, yetkisiz erişim, bozuk girdi, timeout ve servis kesintisi testlerini dahil et.
- Güvenlik kontrolünü yalnızca kod incelemesiyle değil, mümkün olduğunda testle doğrula.
- Testleri geçsin diye testi gevşetme veya assertion silme.
- Başarısız testleri ve kök nedenlerini raporla.
- `PASS`, `FAIL`, `BLOCKED`, `NOT RUN` durumlarından birini ver.
- Sonunda faz kabul matrisi için önerilen durumu ve kalan riskleri bildir.
- Test geçmeden sonraki fazın kodlamasına başlama.
