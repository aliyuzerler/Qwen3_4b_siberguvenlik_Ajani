# Faz 03 Doğrulama — Normalizasyon, Redaction ve Depolama

Tarih: 2026-10-27 · Faz: 03 · Durum: **PASS** (sandbox kapsamı; saha adımları aşağıda NOT RUN)

## 1. Kapsam ve yaklaşım

Faz 03, Wazuh alert'lerini sürümlenmiş ortak event modeline dönüştürür
(`NormalizedEvent`, `schema_version=1`), hassas alanları yapılandırılabilir
politikayla maskeler ve idempotent olarak `events` tablosuna yazar. Tüm
geliştirme mock-first yapıldı: testler sqlite+aiosqlite üzerinde koştu,
Wazuh kaynağı sentetik fixture'lı mock'tur. Gerçek PostgreSQL/Wazuh
doğrulaması saha adımıdır (bkz. §6 NOT RUN).

## 2. Gereksinim → kanıt matrisi

| Gereksinim (phases/03) | Uygulama | Kanıt (test) |
|---|---|---|
| Sürümlenmiş event modeli | `NormalizedEvent` + `EVENT_SCHEMA_VERSION=1` | `test_schema_version_is_set`, `test_model_assessment_not_in_event` |
| Orijinal ID/zaman/agent/rule/severity korunur | Kontrollü eşleme; `rule_level` kanonik int (0-15) | `test_happy_path_maps_controlled_fields`, `test_original_severity_preserved_as_int` |
| Model değerlendirmesi ayrı alanda | Event modelinde `ai_assessment` YOK; Faz 04'te ayrı `analyses` tablosu | `test_model_assessment_not_in_event` |
| UTC timestamp + idempotency key | `UTCDateTime` TypeDecorator (okumada da UTC); `idempotency_key=sha256(source:alert_id)` UNIQUE | `test_received_at_is_utc_aware`, `TestIdempotencyKey`, `test_original_fields_persisted` |
| Kontrollü alan eşlemesi | Whitelist alanlar; rastgele passthrough yok (ham yalnızca opsiyonel `raw_alert`) | `test_happy_path_maps_controlled_fields` |
| Yapılandırılabilir redaction | `REDACTION_ENABLED/REDACT_IP_MODE/REDACT_EMAIL_MODE/REDACT_SECRET_PATTERNS` | `tests/test_redaction.py` (19 test) |
| IP maskeleme ayarlanabilir | `none / masked (IPv4 /24, IPv6 /64) / redacted` | `TestIpMasking` |
| Hassas alanlar maskelenir (saklanan bağlam) | full_log + description secret/e-posta maskesi; src_ip politikalı | `test_secrets_masked_in_stored_context`, `test_secrets_not_in_stored_row` |
| DB migration + indeksler + retention | Alembic `0001_events`; ix timestamp/(source,alert_id)/fingerprint; `RETENTION_DAYS=30` | `tests/test_migrations.py`, `tests/test_retention.py` |
| Tekrar alert çoğaltmasın | UNIQUE kısıt; duplicate → `seen_count+1`, yeni satır yok | `test_duplicate_does_not_create_row`, `test_second_cycle_does_not_duplicate` |
| Aynı ID değişik payload | fingerprint karşılaştırması; ilk yazan kazanır, `variant_count+1` | `test_same_id_different_payload_keeps_first`, `test_variant_does_not_change_rule_level` |
| Ham log gereksiz çoğaltılmasın | `STORE_RAW_ALERT=false` varsayılan; gerekçe §4 | `test_raw_stored_only_when_provided` |
| DB hata/transaction davranışı | Event başına transaction; retryable StorageError fail-fast; unique yarışı yeniden sınıflandırma | `TestDbOutage`, `TestStoreBatch` |
| Güvenilmeyen girdi | Desenler doğrusal (backtracking yok); full_log 8192 karakter tavan; loglama redaction processor'ından geçer | `test_large_input_processed_linearly`, `test_full_log_truncated_to_limit` |

## 3. Test sonuçları (sandbox'ta GERÇEK koşuldu)

- `pytest tests/ -q` → **133 passed, 0 failed, 0 skipped**
  (Faz 01+02'den 58 test + Faz 03 için 75 test; uyarı yok)
- `ruff check .` → **All checks passed!**
- `mypy app` → **Success: no issues found in 31 source files**
- Canlı smoke: uvicorn (mock mod) → `/api/v1/health` 200 `{"status":"ok"}`;
  `/api/v1/ready` 200 `{"database":"up","wazuh":"up","ollama":"not_configured"}`;
  `X-Request-ID` passthrough ✓
- Canlı uçtan uca (sqlite): döngü1 stored=6; döngü2 duplicate=6; satır=6
  (ikinci turda çoğaltma yok — idempotency canlı doğrulandı)

## 4. Saklama gerekçesi (phases/03: "saklama gerekçesini belgele")

- **`full_log_redacted` saklanır:** analiz bağlamının çekirdeğidir; kural
  açıklaması tek başına yetersiz kalır (ör. brute force IP'si, hedef kullanıcı).
  Ham hali yerine MASKELİ hali saklanır: parola/token/e-posta/IP maskeleme
  politikası yazımdan önce uygulanır; secret'lar hash'e bile girmez.
- **`raw_alert` varsayılan SAKLANMAZ:** normalizasyon alanları panel + analiz
  ihtiyacını karşılar; ham kopya depolamayı ikiye katlar ve maskelenmemiş
  hassas içerik yüzeyi açar. Yeniden işlem (re-normalization) gerekiyorsa
  kaynak doğrusu Wazuh Indexer'da mevcuttur (kendi retention'ı ile). Şart
  gerektiğinde `STORE_RAW_ALERT=true` ile izlenebilirlik için açılabilir.
- **`events` 30 gün saklanır (`RETENTION_DAYS=30`):** Faz 04'te `analyses`
  tablosu event_id FK + ON DELETE CASCADE ile bağlanacaktır; analiz, olaydan
  bağımsız yaşamaz. Purge fonksiyonu (`purge_expired_events`) timestamp
  indeksini kullanır; zamanlanmış döngü Faz 04 worker'ıyla etkinleşir.

## 5. DB erişim yetkileri ve transaction davranışı

- **Çalışma zamanı yetkileri (en az ayrıcalık):** uygulama kullanıcısı için
  `SELECT/INSERT/UPDATE(events.seen_count, events.variant_count, events.last_seen_at)`
  yeterlidir; `DELETE` yalnızca retention işini çalıştıran hesapta gerekir.
  DDL çalışma zamanında YAPILMAZ — migration ayrı yürütülür (deploy adımı).
- **Transaction modeli:** event başına tek transaction. Bozuk tek event
  batch'i bloklamaz (NormalizationError izole edilir); retryable DB hatasında
  batch fail-fast kesilir ve aynı veri idempotency sayesinde güvenle tekrar
  yazılabilir. Eşzamanlı insert yarışı `idempotency_key` UNIQUE kısıtıyla
  çözülür: IntegrityError alan taraf satırı yeniden okuyup sınıflandırır.
- **Append-baskın ilke:** duplicate/variant durumunda saklanan satırın
  alert içeriği ASLA güncellenmez; yalnızca sayaçlar ve `last_seen_at` döner.

## 6. NOT RUN (sandbox kısıtı) — saha doğrulama komutları

| Adım | Komut (kullanıcı makinesinde) |
|---|---|
| Compose + gerçek PostgreSQL migration | `cp backend/.env.example backend/.env` (değerleri doldur) → `docker compose up --build` → `docker compose exec backend alembic upgrade head` |
| PG'de rollback testi | `docker compose exec backend alembic downgrade base` → `alembic upgrade head` |
| Gerçek Wazuh ile döngü | `WAZUH_SOURCE_MODE=indexer` + staging hesabı (bkz. docs/wazuh-staging.md) sonrası döngü loglarında stored/duplicate sayaçları izlenir |

## 7. Bilinen sınırlar / sonraki fazlara notlar

- `with_for_update(skip_locked=True)` PostgreSQL'de satır kilidi verir;
  SQLite bunu yok sayar (test ortamı için yeterli — yarış güvenliği UNIQUE
  kısıtı + yeniden sınıflandırma ile sağlanır).
- Zamanlanmış ingest/retention döngüsü bilinçli olarak Faz 04'e bırakıldı
  (analysis worker ile tek döngü; `run_ingest_cycle` yeniden kullanıma hazır).
- `analyses` tablosu (ai_assessment, event_id FK) Faz 04'te eklenecek;
  downgrade sırası o fazda belgelenecek.
