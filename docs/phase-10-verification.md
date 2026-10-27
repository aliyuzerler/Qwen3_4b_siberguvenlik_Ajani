# Faz 10 Doğrulama Raporu — Dağıtım ve Operasyon

Geliştirici koşum raporu (geliştirme ortamı: sandbox — Docker/Ollama/Wazuh YOK).
Bağımsız doğrulama: TEST-PROMPT-TEMPLATE.md uyarınca ayrı doğrulayıcı ajan.
Faz: `phases/10-deployment-and-operations.md`; kabul satırı: **11 "Dağıtım"**
(matriste "10 Fine-tuning (opsiyonel)" satırı Faz 09'da ERTENİR kararıyla
kapalıdır — docs/phase-09-benchmark.md §fine-tuning).

## 1. Teslim edilenler

| Dosya | İçerik |
|---|---|
| `docs/phase-10-operations.md` | Operatör runbook'u: ön koşullar + sürüm matrisi, A-J kurulum akışı (beklenen çıktılı), Ollama/Wazuh/health/smoke/test-alert/analiz/panel doğrulamaları, izleme eşik tablosu, kesinti davranış matrisi, upgrade/rollback checklist, bakım takvimi, NOT RUN komutları |
| `scripts/phase10_smoke.sh` | 7 evreli uçtan uca operasyon smoke (33 kontrol) |
| `scripts/fake_ollama_server.py` | Bozuk-çıktı Ollama düzeneği (fallback yolu; TEST aracı — kanıt değil) |
| `scripts/seed_staging_events.py` | Sentetik test-alert besleyici (ÜRETİM ingest yolu: parse→normalize→redact→idempotent store; ŞİMDİ damgalı → saat-bağımsız) |
| `scripts/backup_db.sh` | Faz 10 sertleştirmesi: EXIT trap (başarısız koşum yarım dump bırakmaz) |
| `docs/deployment.md` | §7 trap notu |

## 2. Gereksinim→kanıt matrisi (phases/10 içerik maddeleri)

| Faz 10 maddesi | Kanıt | Durum |
|---|---|---|
| Ön koşullar ve sürüm sabitleme | operations.md §1 (10 satırlık pin matrisi; kilit dosyalarıyla tutarlı) | KANITLI |
| Secret/env kurulumu | operations.md §2-B tablosu + deployment.md §3; `.env` git-dışı (secret_scan) | KANITLI |
| Database migration ve backup | §2-E/F (compose başlangıcı alembic), §10 takvim, smoke Evre 7 script sözleşmesi | KANITLI (koşum kısmı NOT RUN) |
| Wazuh bağlantı kurulumu | §4 + wazuh-staging.md (salt okunur hesap; 403 yazma reddi doğrulaması) | KANITLI (bağlantı koşumu NOT RUN) |
| Ollama indirme/doğrulama | §3 (loopback bağlama, pull/show/ps, konteyner→host testi, benchmark check) | KANITLI (koşum NOT RUN) |
| Health check ve smoke test | §5 (bileşen tablosu) + phase10_smoke 33/33 + phase08_smoke referansı | KANITLI (sandbox koşumu) |
| Test alert → AI analizi | §6 senaryo tablosu + seed_staging_events.py + smoke Evre 2/3/4 | KANITLI (sandbox sözleşmesi) |
| Model/Wazuh kesilirse güvenli davranış | §8 matrisi (kod kanıtlı) + smoke Evre 3/4/5 | KANITLI (sandbox koşumu) |
| Log/metric izleme ve alarm eşikleri | §7 eşik/aksiyon tablosu (10 sinyal) + deployment.md §5-6 | KANITLI |
| Upgrade ve rollback | §9 checklist + deployment.md §8-9 + incident-runbook §7 | KANITLI (koşum NOT RUN) |
| Incident response ve bakım | §10 bakım takvimi + incident-runbook.md 9 senaryo | KANITLI |

## 3. Sandbox koşum kanıtları (geliştirici koşumu)

- `scripts/phase10_smoke.sh`: **33 PASS / 0 FAIL** (exit 0), 7 evre:
  1. Temiz kurulum: alembic head → /health 200 → /ready (database=up,
     wazuh=up[mock], ollama=down, disk raporlu) → bootstrap admin girişi.
  2. Test alert besleme: `seed_staging_events.py` **6 stored**; tekrar koşum
     **stored=0** (idempotency_key tekil; yeni satır YOK), duplicate+variant=6,
     failed=0. Saat-bağımsızdır (ŞİMDİ damgalı).
  3. **Model kesik** (ölü port, worker döngüsü açık): /ready ollama=down;
     6 event saklı; **analysis=None** (SAHTE değerlendirme YAZILMAZ —
     analysis.py "altyapı hatası satır yazmaz" sözleşmesi); `worker_cycle_failed`
     loglandı (döngü ÇÖKMEDİ); süreç /health 200.
  4. **Model bozuk çıktı** (`fake_ollama_server.py`, geçerli zarf + geçersiz
     model JSON): /ready ollama=up; **6/6 event `analysis_failed`** (retry
     tükenimi → güvenli fallback, analyzer.py çıktı ailesi); **completed=0**
     (uydurma değerlendirme yok); `worker_analysis_cycle` loglandı; panel
     /overview + /agents 200; model künyesi `qwen3:4b`; audit'te
     `auth.login.success` izi; anonim /events 401.
  5. **Wazuh kesintisi** (ölü indexer URL): /ready wazuh=down, genel 200
     (yalnız DB 503'tür), saklı 6 olaya erişim SÜRÜYOR.
  6. **Kill switch**: ANALYSIS_ENABLED=false → /ready ollama=disabled.
  7. **Backup sözleşmesi**: Docker'sız backup_db.sh fail-fast (exit != 0) +
     **yarım dump artığı YOK** (YENİ: EXIT trap); restore_db.sh onaysız koşum
     exit 1, argümansız çağrı exit 2.
- Regresyon kapıları (aynı commit): pytest **641/641**, ruff temiz, mypy
  (87 dosya) temiz, vitest 31/31, `npm run build` 14 route, secret_scan exit 0.
  (Bkz. §4 — üretim app/ koduna dokunulmadığından sayılar Faz 09 ile aynıdır.)

## 4. Mimari kararlar

- **Smoke saat-bağımsız tasarım**: donmuş fixture zaman damgaları (~2026-10-26)
  worker ilk penceresi (≤86400 sn) kısıtıyla duvara çarpar → besleme ÜRETİM
  ingest yoluyla (MockWazuhAlertSource + run_ingest_cycle) ŞİMDİ damgalı
  sentetik alert'lerle yapılır. MockWazuhAlertSource zaten Faz 02'den beri
  test sözleşmesidir; seed scripti yeni bir paralel yol DEĞİL, aynı parse →
  normalize → redact → idempotent store zincirini çağırır.
- **fake_ollama_server.py kanıt disiplini**: geçerli zarf + geçersiz model
  metni döndürerek analyzer'ın ÇIKTI ailesini (analysis_failed) tetikler —
  transport ailesini değil. Çıktıları model kanıtı SAYILMAZ (Faz 09
  `results_valid_as_model_evidence=false` muadili, runbook §6 uyarısıyla).
- **backup EXIT trap**: `trap - EXIT` yalnızca TAMAM sonrası kaldırılır →
  prune adımındaki hata geçerli yedeği silemez (bilinçli sıra).
- **seed scriptinin alembic çalıştırmaması**: şema uygulaması kurulum adımıdır
  (compose başlangıcı); besleyici tek sorumluluk taşır.

## 5. Kalan riskler

- Runbook'un gerçek staging'de baştan sona koşumu bağımsız operatörle YAPILMADI
  (sandbox kısıtı) — phases/10 test promptunun "temiz staging ortamında
  uygula" kalemi kullanıcı makinesine açık kalır (§6 komut listesi).
- fake_ollama_server tek iş parçacıklı stdlib sunucusudur: yüksek eşzamanlılıkta
  (WORKER_CONCURRENCY>8 gibi) kuyruk gecikmesiabilir; test düzeneği için kabul.
- Alarm eşikleri (§7) operasyonel sezgiyle sabitlendi; gerçek trafikte kalibre
  edilmeli (önerilen: 2 hafta sonra gözden geçirme).

## 6. Kullanıcı makinesinde koşulacaklar (staging; sırayla)

```bash
git pull && git checkout <bu-commit>
docker compose up -d --build
docker compose logs backend | grep alembic            # migration tamam mı
curl -s http://127.0.0.1:8000/api/v1/ready            # 4 bileşen beklenen mi
ollama pull qwen3:4b
DATABASE_URL="postgresql+asyncpg://ajant:<parola>@127.0.0.1:5432/ajant" \
  python3 scripts/seed_staging_events.py              # {"stored":6,...}
# .env: WORKER_LOOP_ENABLED=true → docker compose up -d backend
sleep 45 && docker compose logs backend | grep worker_analysis_cycle
# beklenen: completed>0 (gerçek model)
./scripts/backup_db.sh ./backups                      # TAMAM çıktısı
./scripts/restore_db.sh backups/<son-dump>            # evet onayı (staging!)
```

Tam senaryo listesi: `docs/phase-10-operations.md` §2 (A-J) ve §12.

## 7. Sonuç

Geliştirici koşumu: **PASS** — kabul satırı 11'in beş ölçütünden dördü
(staging akış sözleşmesi, backup, monitoring, rollback planı + dokümantasyon)
test/koşumla kanıtlı; beşincisi (gerçek staging uçtan uca doğrulama) sandbox
kısıtıyla **NOT RUN** ve §6 komut listesiyle kullanıcıya bırakılmıştır.
