# Fine-tuning geliştirme promptu (yalnızca T1–T3 ölçümleri tamamlandıktan sonra)

Qwen3 4B tabanlı güvenlik olay analizi modelini fine-tune etmek için deney altyapısı tasarla; henüz eğitim başlatma.

Önce baseline raporunu ve etiketli veri kümesini incele. Fine-tuning'in hangi ölçülebilir hata sınıfını çözmesi gerektiğini açıkla. Veri lisansı, gizlilik, duplicate/leakage, sınıf dengesizliği ve etiket kalitesini kontrol et.

Ardından:
1. Uyumlu model/tokenizer/chat template ve lisans gereksinimlerini doğrula.
2. LoRA/QLoRA gibi parametre-verimli bir pilot yaklaşım öner.
3. Donanım ve bellek gereksinimini tahmin et; tahmini gerçek benchmark ile doğrulama adımı ekle.
4. Train/validation/test split'lerini sabitle; test setine eğitim sırasında erişme.
5. Tekrarlanabilir config, seed, checkpoint ve artifact hash planı oluştur.
6. Eğitim metrikleri dışında holdout güvenlik metriklerini hesaplayan değerlendirme kodu planla.
7. Base model ile fine-tuned modeli aynı test setinde karşılaştır.
8. Kritik metrikler kötüleşirse yayınlamayı durdur.
9. Staging/shadow deployment ve rollback planı hazırla.

İlk olarak yalnızca deney planını, dosya yapısını ve kabul kriterlerini sun. Eğitim başlatmak, veri yüklemek veya mevcut model dosyalarını değiştirmek için onay bekle.
