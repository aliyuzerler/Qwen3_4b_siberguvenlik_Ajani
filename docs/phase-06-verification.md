# Faz 06 Doğrulama Raporu — Korelasyon ve Değerlendirme

Faz: `phases/06-correlation-and-evaluation.md`
Tarih: 2026-10-27
Kapsam: kural tabanlı korelasyon katmanı (deterministik, LLM'siz) + etiketli
sentetik senaryo suite + panel görüntüleme + admin kural toggle (audit'li).

## 1. Gereksinim → Kanıt Matrisi

| # | Gereksinim (phases/06) | Uygulama | Kanıt |
|---|---|---|---|
| 1 | Yapılandırılabilir zaman pencereleri ve kurallar | `CORRELATION_ENABLED/LOOKBACK_SECONDS/MAX_EVENTS_PER_RUN` (config) + sürümlenmiş kural kataloğu (`services/correlation/rules.py`, Pydantic `CorrelationParams`: window_seconds/threshold/group_by/filtreler) + DB `correlation_rules` tablosu (enabled operatör anahtarı) | `tests/test_correlation_rules.py` (14 test); config doğrulama; PATCH API audit'li |
| 2 | Ortak agent, IP, kullanıcı, süreç, alert ID alanlarıyla ilişki | `group_by` alanları: agent_id/agent_name/src_ip/rule_id (composite destekli — `["agent_id","rule_id"]`); evidence: agent_names, src_ips, matched_rule_ids, alert_ids | `tests/test_correlation_engine.py` grup ayrımı testleri; senaryo `farkli_sunucular` (2 ayrı tespit) |
| 3 | Her korelasyonda hangi olaylar + hangi kural eşleşti göster | `correlations` satırı rule_key + rule_version taşır; `correlation_events` kanıt bağlantıları (her event FK'li); evidence.alert_ids zaman sıralı; API detay `/correlations/{id}` bağlı olayları listeler | `test_correlation_api.py::test_detail_includes_linked_events_and_rule` (event_count == len(events)); senaryo testi bağlantı↔event_count tutarlılığı |
| 4 | Duplicate/near-duplicate yönetimi | (a) Event düzeyi: Faz 03 idempotency (seen_count). (b) Korelasyon düzeyi: `dedup_key` UNIQUE = sha256(rule\|grup\|pencere_başlangıcı) — aynı olay kümesi yeniden tespit edilirse yeni satır YAZILMAZ, hit_count+1, eksik bağlantılar eklenir | `test_correlation_repository.py::test_same_detection_again_is_hit_not_new_row`, `test_extended_cluster_links_new_events_only`; senaryo `duplicate_event` (2 tur → hit_count=2, bağlantı=5 unique) |
| 5 | Kural sürümü ve audit kaydı | `rule_version` her tespitte kaydedilir; katalog senkronu sürüm artışını audit'ler (`correlation.rule.synced`, actor=system); admin toggle audit'i (`correlation.rule.updated`, actor=kullanıcı); operatör enabled kararı deploy ile SIFIRLANMAZ | `test_correlation_repository.py::test_version_bump_updates_and_audits`, `test_sync_preserves_operator_enabled`; `test_correlation_api.py::test_admin_can_toggle_and_audit_is_written` |
| 6 | Sentetik, etiketli test senaryoları | `tests/fixtures/correlation_scenarios.json`: meta.synthetic=true + license "GERCEK SALDIRI VERISI DEGILDIR" + senaryo başına benign/malicious label + SENTETİK ibaresi; 7 senaryo | `tests/test_correlation_scenarios.py` (fixture etiketi test tarafından DOĞRULANIR — etiketsiz fixture suite'i dolduramaz) |
| 7 | Kural çıktısı ↔ LLM yorumu ayrı | Korelasyon tablo/şema/tip te KESİNLİKLE ai_* alanı yok; LLM kaydı yalnızca `analyses` (olay başına); API detayında model kaydı her olayın AYRI `analysis` nesnesinde; panelde kural kartı ("kural motoru çıktısı" rozeti) ↔ olay satırlarında mor AI rozetleri | `test_correlation_api.py::TestAnalysisSeparation`; frontend `tests/correlations.test.tsx` |

Kabul matrisi satır 06: "Zaman pencereleri, tekrarlar, kanıt bağlantıları ve
sentetik senaryo testleri" → tamamı yukarıda test+canlı kanıtla karşılandı.

## 2. Mimari Kararlar

1. **LLM tek başına ilişkilendirme kaynağı DEĞİL**: motor saf, deterministik
   (kayan pencere + eşik; sıralı çiftleme). ML/anomali algoritması kasıtlı
   YOKTUR (phases/06: "basit ve açıklanabilir kurallar").
2. **İki kural türü**: `burst` (eşik + pencere, grup bazlı) ve `sequence`
   (önce→sonra çiftleme; her ikinci olay en fazla bir kez tüketilir).
3. **Katalog koddadır, DB yansımasıdır**: seed/senkron startup'ta; params
   doğrulaması Pydantic ile; `enabled` DB'de yaşar (operatör kararı kalıcı).
4. **Korelasyon → analiz sırası**: worker döngüsünde korelasyon analizden
   ÖNCE çalışır. Gerekçe: Ollama kapalıyken analiz fail-fast turu bitirir;
   korelasyonun (yerel, harici bağımlılıksız) savunma sürekliliği model
   erişimine bağlanmamalı. Canlı smoke ile kanıtlandı (Ollama down iken
   tespit üretildi).
5. **Append-baskın kayıt modeli**: correlations üzerinde UPDATE yalnızca
   hit_count/last_hit_at (events.seen_count kalıbı); DELETE kod yolu yok;
   retention events FK CASCADE ile temizler.
6. **Eksik alan politikası**: group_by bileşeni None olan event o kural için
   elenir (None==None sahte gruplaşması yasak; senaryo `eksik_alan`).
7. **Gecikme ölçümü**: event→tespit latency = tespit anı − window_end;
   her tespit loglanır (`correlation_detection_saved.latency_seconds`).
8. **Kapsam notu — kullanıcı/süreç alanları** (bağımsız doğrulama F3): faz
   metni "kullanıcı, süreç" alanlarıyla ilişkiden söz eder; normalize event
   modeli (Faz 03 şeması v1) bu kolonları taşımaz. Bu fazda ilişki alanları
   agent_id/agent_name/src_ip/rule_id ile SINIRLIDIR. Kullanıcı/süreç
   desteği NormalizedEvent schema v2 + migration adayı olarak not edilmiştir
   (kaynak verideki data.* alanlarının normalizasyonuyla birlikte ele alınır).
9. **Analiz kill switch artık döngüde uygulanır** (bağımsız doğrulama F1
   kapanışı): ANALYSIS_ENABLED=false iken döngü Ollama'ya çağrı YAPMAZ
   (/ready "disabled" ile aynı anlambilim); korelasyon bu switch'ten
   etkilenmez.

## 3. Çalıştırılan Testler (gerçek sonuçlar)

- `pytest tests/ -q` → **457 passed**, 0 failed (~100s). (Faz 05: 366 → +91)
  - Yeni: rules 19, engine 24, repository 14, cycle 8, API 20, senaryo 1
    (7 senaryo içeren suite), migration +3, worker-loop +2 (Faz 06 entegrasyonu).
- `ruff check .` → All checks passed.
- `mypy app/` → Success: no issues found in 66 source files.
- Alembic: upgrade head (0001→0004) + downgrade 0003 + re-upgrade turu →
  `tests/test_migrations.py` 13/13; canlı `alembic upgrade head` smoke'ta.
- Frontend: `npx vitest run` → **19 passed** (4 dosya); `npm run build` →
  başarılı; yeni rotalar: `/correlations`, `/correlations/[id]`, `/rules`.
- Canlı smoke (uvicorn + sqlite + mock Wazuh + Ollama kapalı, ANALYSIS_ENABLED=false):
  **14/14 PASS** — `/health`, `/ready` (db:up, wazuh:up, ollama:disabled),
  login, katalog seed (3 kural), PATCH toggle (updated/unchanged/401),
  worker korelasyon turu (events_scanned=6, rules_evaluated=3; analiz
  kill switch'i sayesinde `worker_cycle_failed` YOK — F1 kapanışının canlı
  kanıtı), canlı tespit (failed_login_burst + repeated_alert; ikinci turda
  `hits=2 new=0` — idempotency canlı), audit kaydı (2), log credential
  taraması temiz. Script: `scripts/phase06_smoke.sh`.

### Sentetik senaryo metrikleri (suite geneli)

```
Senaryo                                Etiket     Tahmin                       Beklenen
normal_bakim                           benign     {}                           {}
basarisiz_login_burst                  malicious  {burst, tekrar}              {burst, tekrar}
giris_sonrasi_supheli_degisiklik       malicious  {sıralı}                     {sıralı}
duplicate_event                        malicious  {burst, tekrar}              {burst, tekrar}
farkli_sunucular                       malicious  {burst ×2, tekrar ×2}        {burst, tekrar}
zaman_sirasi_bozuk                     malicious  {burst, tekrar}              {burst, tekrar}
eksik_alan                             benign     {}                           {}

TP=9  FP=0  FN=0  TN=12
precision=1.0000  recall=1.0000  FPR=0.0000
max event→tespit latency (senaryo ortamı) = 6840.0s (döngü zamanı sabit
NOW=11:00'a göre; üretimde tur aralığı kadar — WORKER_INTERVAL_SECONDS)
```

Not: Bu metrikler KORELASYON motorunun etiketli suite üzerindeki ölçümüdür;
model (Qwen3) ölçümü değildir — o ayrı Faz 09 holdout gerektirir.
Deterministik kurallar + sabit etiketler → kusursuz sınıflandırma beklenir;
suite'in değeri REGRESYON duyarlılığıdır (kural bozulursa suite kırmızıya
döner) ve FPR davranışının (benign senaryolarda 0 tespit) kanıtıdır.

## 4. Değişen Dosyalar

- Backend yeni: `app/services/correlation/` (errors, rules, engine,
  repository, __init__), `app/models/correlation.py`,
  `alembic/versions/0004_correlations.py`, `app/workers/correlation.py`,
  `app/api/v1/correlations.py`, testler (6 dosya) + fixture JSON.
- Backend değişen: `app/models/__init__.py`, `app/core/config.py`,
  `app/workers/loop.py` (sıra + parametreler), `app/main.py` (senkron +
  wiring + CORS PATCH), `app/api/v1/{router,schemas}.py`,
  `app/services/security/audit.py` (2 yeni eylem), `.env.example`.
- Frontend yeni: `src/app/correlations/page.tsx`,
  `src/app/correlations/[id]/page.tsx`, `src/app/rules/page.tsx`,
  `tests/correlations.test.tsx`. Değişen: `src/lib/{api,types}.ts`,
  `src/components/panel-shell.tsx` (2 yeni nav öğesi).

## 5. NOT RUN (sandbox kısıtı — kullanıcı makinesinde yapılacak)

1. **Gerçek PostgreSQL migration**: `docker compose exec backend alembic
   upgrade head` (0004 PG'de; JSONB variant, FK davranışı PG'de doğrulanmalı).
2. **Gerçek Ollama uçtan uca**: korelasyon + panelde AI rozetlerinin birlikte
   görünümü (`WORKER_LOOP_ENABLED=true` + gerçek `qwen3:4b`).
3. **Gerçek Wazuh verisiyle kural ayarı**: gerçek rule ID/group dağılımına
   göre `failed_login_burst` (5710/5712/5716/5760…) ve sequence filtrelerinin
   (550/553/554/591) saha eşleştirmesi — katalog v2 adayı (sürüm artışıyla).
4. **Gerçek tarayıcı görsel incelemesi**: /correlations ve /rules sayfaları.
5. **Çok proses dağıtım**: tek-yazar varsayımı (dedup_key yarışı UNIQUE +
   retry ile korunur ama iki backend replikası bu fazda desteklenmez).

## 6. Bilinen Sınırlar / Riskler

- **Dedup anahtarı lookback'e bağlı**: burst'un İLK eventi lookback
  penceresinden çıkarsa ve burst sürüyorsa, devam için yeni bir tespit
  satırı açılabilir (belgelenmiş kısıt; varsayılan lookback 6 saat — pratik
  etki düşük).
- **Aynı event birden çok kurala girebilir** (örn. burst + tekrar): kasıtlı
  tasarım — her kural farklı soruya cevap verir; panelde kural bazlı gruplanır.
- **Rate limit / audit retention**: Faz 08 kapsamında (önceki faz notları).
- `src_ip` gruplaması REDACTION maskeli modda alt ağ düzeyindedir (IPv4 /24)
  — gizlilik tercihiyle uyumlu, kaba kuvvet kaynağı analizini alt ağ
  çözünürlüğüne sınırlar.
- **Katalog sürüm disiplini** (bağımsız doğrulama F5): params değişikliği
  ancak version artışıyla DB'ye yansır; aynı sürümde params farkı tespit
  edilirse uyarı loglanır (`correlation_rule_params_drift`) ama DB
  değiştirilmez (determinizm korunur).

## 6a. Bağımsız Doğrulama (Task 6-test) Bulgu Kapatma Tablosu

| Bulgu | Önem | Karar | Kapanış |
|---|---|---|---|
| F1: ANALYSIS_ENABLED kill switch döngüde uygulanmıyordu (Faz 04'ten taşınan) | orta | DÜZELTİLDİ | `run_worker_loop`/`_run_once`'a `analysis_enabled` parametresi; false iken Ollama çağrısı YAPILMAZ; test: `test_analysis_kill_switch_skips_analysis_but_not_correlation` |
| F2: sequence match_*/then_* çakışması → sessiz 0 tespit | orta | DÜZELTİLDİ | `CorrelationParams` validator'ı ayrıklık zorunlusu (kesişim → ValidationError); 3 yeni test (ids, groups, katalog) |
| F3: kullanıcı/süreç alanları event modelinde yok | düşük | BELGELENDİ | §6. Mimari Kararlar madde 8: NormalizedEvent schema v2 adayı olarak kayda alındı |
| F4: loop docstring adım sırası kodla çelişiyordu | düşük | DÜZELTİLDİ | docstring güncellendi (1=ingest, 2=korelasyon, 3=analiz) |
| F5: params drift sürüm artışı olmadan sessiz kalırdı | düşük | DÜZELTİLDİ | aynı sürümde params farkı → `correlation_rule_params_drift` uyarı logu |
| F6: doğrulama dokümanı test sayı hataları | bilgi | DÜZELTİLDİ | bu doküman güncellendi (rules 19, engine 24) |
| F7: commit bekleniyor | bilgi | YAPILIYOR | bu kayıtla commit |
| F8: worklog geliştirici kaydı | bilgi | YAPILIYOR | Task 6 kaydı eklendi |
| F9: toggle + audit ayrı transaction | bilgi | KABUL (bilinçli) | Faz 05 kararı: "audit hatası akışı bozmaz/ kilitleme vektörü olmaz" |
| F10: rules/page.tsx boş attribute satırı | bilgi | DÜZELTİLDİ | temizlendi |
| F11: loop seviyesinde korelasyon entegrasyon testi yok | bilgi | DÜZELTİLDİ | `TestCorrelationIntegration` (2 test: model kesintisinde korelasyon devam eder; kill switch yolu) |

## 7. Sonraki Küçük Adım

Faz 07 — Müdahale güvenliği (dry-run politik motoru, allowlist, insan onayı,
timeout, rollback/kill switch).
