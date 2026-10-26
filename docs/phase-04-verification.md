# Faz 04 Doğrulama Raporu — Ollama/Qwen3 4B Analiz Worker'ı

Durum: **Geliştirici doğrulaması PASS** (bağımsız doğrulayıcı raporu ayrı tutulur)
Tarih: 2026-10-27
Kapsam: phases/04-qwen-analysis.md + acceptance-matrix.md satır 04
("Ollama bağlantısı, katı şema, timeout, invalid JSON fallback, prompt injection testleri")

## 1. Yapılan değişiklikler

- `app/services/analysis/` paketi: tipli hata hiyerarşisi (aktarım ailesi ↔ model çıktı
  ailesi ayrımı), katı şema DTO'ları (`ModelAnalysis` extra="forbid"), prompt şablonu v1
  (`<event_data>` güvenilmeyen-veri çerçevelemesi), `HttpOllamaClient` (yalnızca
  /api/generate + /api/version + /api/tags), `EventAnalyzer` (timeout + sınırlı retry +
  semaphore + `analysis_failed` fallback), `AnalysisMetrics` (geçerlilik oranı, p50/p95,
  hata oranı), append-only `AnalysisRepository`.
- `app/models/analysis.py` + `alembic/versions/0002_analyses.py`: analyses tablosu
  (FK events ON DELETE CASCADE, UNIQUE event_id, CHECK status/confidence/assessment bağı).
- `app/workers/analysis.py` (analiz döngüsü) + `app/workers/loop.py` (tek döngü:
  fetch → store → analyze; VARSAYILAN KAPALI `WORKER_LOOP_ENABLED=false`).
- `app/core/config.py`: Ollama/analiz ayarları + **iç ağ host kısıtı**
  (`ollama_allow_public_host=false` iken yalnızca loopback/özel IP/tek-etiket
  hostname/host.docker.internal/*.internal/*.local kabul edilir).
- `app/api/v1/health.py`: /ready Ollama bileşeni → `up | down | model_missing | disabled`.
- `app/core/db.py`: SQLite FK pragma (CASCADE, PG semantiğiyle uyum); `main.py`: istemci +
  metrik + worker wiring; `.env.example` güncellendi.

## 2. Gereksinim → kanıt matrisi

| Gereksinim (phases/04) | Kanıt |
|---|---|
| Yapılandırılabilir yerel model; tag+quantization config'de sabit | `OLLAMA_MODEL_TAG=qwen3:4b`, `OLLAMA_MODEL_QUANTIZATION=Q4_K_M`; künye her analyses satırına yazılır (test: `test_save_completed_row`) |
| Model yoksa açık hata/kurulum talimatı | 404 → `OllamaModelMissingError` + "`ollama pull qwen3:4b`" talimatı (test: `test_404_maps_to_model_missing_with_install_instruction`); /ready `model_missing` (test: `test_ready_ollama_model_missing`) |
| Yalnızca doğrulanmış event context | Bağlam yalnızca events kolonlarından; raw_alert prompt'a girmez (test: `test_no_raw_or_secret_fields_in_payload`, `test_pending_context_carries_masked_fields_only`) |
| Prompt injection → log talimat değil veri | `<event_data>` çerçeveleme + sistem kuralı (test: `test_system_prompt_declares_untrusted_data_rule`, `test_injection_payload_stays_inside_data_block`); serbest komut önerisi enum whitelist dışı → RED (test: `test_wrong_step_enum_rejected_with_free_command`); injection uydurması analysis_failed'e düşer (test: `test_injection_log_is_data_and_output_is_validated`); saldırı metni sistem prompt'una sızmaz (test: `test_injection_does_not_leak_into_system_prompt`) |
| JSON Şema/katı doğrulama | Pydantic extra="forbid"; eksik/ekstra/yanlış enum/aralık dışı/çok uzun → `AnalysisOutputError` (test sınıfları: TestMissingFields, TestExtraFields, TestEnums, TestConfidence, TestTooLongOutput) |
| Timeout, sınırlı retry, cancellation, concurrency | asyncio.timeout per deneme (test: `test_timeout_raises_unavailable`); max_retries üstel backoff (test: `test_invalid_then_valid_output_retries_and_completes`); CancelledError sızdırılır (test: `test_external_cancel_propagates`); Semaphore (test: `test_semaphore_limits_in_flight_calls`, max_in_flight ≤ 2) |
| Geçersiz çıktı → güvenli fallback `analysis_failed` | Çıktı ailesi retry tükenince `AnalysisOutcome.failed` → analyses satırı (test: `test_missing_field_exhausts_retries_then_failed`, `test_invalid_output_writes_analysis_failed_row`) |
| Model sürümü/süre/şablon/metadata kaydı | analyses: model_tag, model_quantization, prompt_template_version, prompt_chars, context_chars, context_truncated, duration_ms, retries_used, finished_at (test: `test_save_completed_row`) |
| Orijinal Wazuh severity değişmez | `ModelAnalysis`'ta severity/rule_level alanı YOK (extra="forbid" reddeder; test: `test_model_cannot_produce_severity_field`, `test_analysis_never_touches_original_severity`); events satırı analizden etkilenmez (test: `test_analysis_failure_does_not_touch_event_severity`) |
| Sadece analiz; tool calling/shell yok | İstek gövdesinde tools/functions yok (test: `test_no_tool_or_shell_parameters_sent`); API yüzeyi 3 salt uç nokta; öneriler enum whitelist |
| Model API yalnızca iç ağ/localhost | Config validator: genel FQDN/IP reddedilir (test: `TestOllamaHostRestriction` — 10 iç host ACCEPT / 4 genel host REJECT / escape hatch / şema; doğrulayıcı bulgusu B1 sonrası eklendi) |
| Wazuh/Ollama kesintisi, DB hatası negatif yolları | Ollama kapalı/5xx → döngü fail-fast, SATIR YAZILMAZ (test: `test_ollama_down_writes_no_rows_and_raises`); kısmi batch pending kalır (test: `test_partial_batch_stays_pending_after_abort`); worker döngüsü çökmez (test: `test_loop_survives_infrastructure_failure`); kalıcı DB hatası izole (test: `test_non_retryable_db_error_isolated`) |
| Tekrar gelen event aynı analizi çoğaltmaz | UNIQUE event_id → skipped (test: `test_duplicate_event_id_yields_skipped_race`); ikinci döngüde pending boş (test: `test_second_cycle_has_no_pending`) |
| Retention: analiz olaydan bağımsız yaşamaz | FK ON DELETE CASCADE (test: `test_event_delete_cascades_analysis`) |

## 3. Çalıştırılan testler ve GERÇEK sonuçlar

```
pytest tests/ -q            → 281 passed, 0 failed (Faz 02-03 tabanı 191 + Faz 04: 90 yeni)
ruff check .                → "All checks passed!"
mypy app                    → "Success: no issues found in 42 source files"
alembic upgrade/downgrade   → 0001↔0002 roundtrip canlı doğrulandı (sqlite)
canlı smoke (uvicorn+mock)  → /health 200; /ready {database: up, wazuh: up, ollama: down};
                              X-Request-ID passthrough ✓; uvicorn log credential taraması temiz
```

### Ölçüm raporu (phases/04: "Başarıyı varsayma; ölçüm sonucu ver")

⚠️ **Aşağıdaki ölçümler MockOllamaClient (sentetik) tabanlıdır; gerçek model ölçümü DEĞİLDİR.**
Sandbox'ta Ollama yoktur (ortam envanteri: Faz 00, risk R4). Gerçek ölçüm saha adımıdır
(§5). Measurement altyapısı (AnalysisMetrics) bu fazda test edildi ve canlıdır.

| Metrik | Mock ölçümü | Not |
|---|---|---|
| Şema geçerlilik oranı (mock) | 0.971 (34/35) | Geçersiz çıktı fixture'ları bilinçli eklenmiştir; gerçek modelde bu oran modelin KENDİ geçerliliğidir |
| Hata oranı (mock) | 0.029 | Yalnızca enjekte edilen geçersiz çıktılar |
| p50 / p95 latency (mock) | 1 / 3 ms | Mock gecikmesi sıfıra yakın; CPU qwen3:4b'de beklenen: saniyeler–dakikalar (WORKER_TIMEOUT_SECONDS=120 tavan) |
| Retry davranışı | 1 geçersiz → 2. deneme tamamlanır (retries_used=1) | Test kanıtlı |

## 4. Mimari kararlar ve varsayımlar

1. **İki hata ailesi ayrımı (temel tasarım kararı):** Ollama/altyapı hataları (bağlantı,
   5xx, timeout, bozuk zarf UTF-8) → döngü fail-fast, analyses tablosuna SATIR YAZILMAZ,
   event'ler pending kalır (sonraki turda idempotent yeniden deneme). Model ÇIKTI
   hataları (invalid_json, schema_violation, output_too_long) → sınırlı retry →
   `analysis_failed` satırı. Gerekçe: Ollama kapalıyken tüm event'lere "model hatası"
   yazmak append-only tabloyu çöp üretimine çevirirdi (AGENTS.md §5/§8 ayrımı).
2. **UNIQUE event_id:** faz başına tek analiz; yeniden analiz (model yükseltmesi)
   gelecek fazda ayrı migration ile açılır. Duplicate ingest analizi yeniden tetiklemez.
3. **Mock analiz modu YOK (bilinçli):** Wazuh'tan farklı olarak analiz için config'de
   mock modu sağlanmadı — sahte AI değerlendirmesi güvenlik ürününde tehlikelidir;
   MockOllamaClient yalnızca tests/ altındadır.
4. **Worker döngüsü varsayılan KAPALI:** `WORKER_LOOP_ENABLED=false` güvenli başlangıç;
   operatör açıkça açar. Tur = ingest (kaynak varsa) + analiz; cursor son event
   zamanından devam eder; başarısız turda cursor ilerlemez.
5. **Jitter'sız üstel backoff** analyzer'da (Faz 02'den farkı bilinçli): test
   determinizmi; CPU tek-model senaryosunda yıldırım sürüsü riski düşük.
6. **`format: "json"` + `num_predict: 512` + `temperature: 0.2`:** katı JSON çıktı ve
   deterministik davranış; 512 token tavanı "çok uzun çıktı" yüzeyini baştan daraltır.
7. **SQLite FK pragma (db.py):** CASCADE semantiği dev/test'te PG ile aynı olur.

## 5. NOT RUN — saha doğrulama adımları (kullanıcı makinesi)

Sandbox'ta Docker/Ollama/PostgreSQL yoktur; aşağıdakiler çalıştırılamadı (çalıştırılmamış
gibi raporlanmadı):

```bash
# 1) Ollama kurulumu + model (CPU modu; 32GB RAM yeterli)
ollama pull qwen3:4b
ollama list   # qwen3:4b görünmeli

# 2) Gerçek model ile uçtan uca
cp backend/.env.example backend/.env   # JWT_SECRET/DATABASE_URL doldurun
docker compose up --build -d
curl -s http://localhost:8000/api/v1/ready   # ollama: up beklenir (yoksa model_missing → pull)

# 3) Worker döngüsünü açın (opsiyonel; .env)
#    WORKER_LOOP_ENABLED=true
#    WAZUH_SOURCE_MODE=mock  (önce sentetik alert ile uçtan uca)
#    sonra docker compose restart backend

# 4) Ölçüm: gerçek model ile şema geçerlilik oranı/p50/p95 — Faz 09 holdout seti
#    ile sistematik ölçülecek; ilk gözlem için backend logundaki
#    worker_analysis_metrics olayına bakın.
```

## 6. Bilinen sorunlar / kalan riskler

- **R4-04 (ortam):** Gerçek qwen3:4b çıktı kalitesi ölçülemedi — katı şema + fallback
  kötü çıktıya karşı savunmayı sağlar, ancak geçerlilik oranı model davranışına
  bağımlıdır; Faz 09 ölçümü zorunlu.
- analyses satırında `requires_human_review` sqlite'ta 0/1 integer saklanır (panelde
  bool'a çevrilir; Faz 05 notu).
- Tek yazar varsayımı: worker döngüsü tek asyncio task; çoklu replika senkronizasyonu
  Faz 08 (hardening) kapsamında.
- Retry-After benzeri sunucu ipucu Ollama API'sinde yoktur; backoff yalnızca istemci
  tarafı üsteldir.
- Mock tabanlı latency ölçümleri gerçek model süresini TEMSİL ETMEZ (§3 uyarısı).

## 7. Bağımsız doğrulayıcı (Task ID: 4-test) sonucu ve bulgu kapatma

Bağımsız doğrulayıcı raporu: **önerilen durum PASS** (262/262 test bağımsız koşum,
~60 Faz 04 testi tekil node-id ile tekrar koşuldu, salt-okunur/tool-yok kanıtı rg ile
üretildi, 13 senaryolu manuel host-kısıtı doğrulaması doğru).

| Bulgu | Önem | Çözüm |
|---|---|---|
| B1: Ollama host kısıtının otomatik regresyon testi yok; doküman iddiası yanlıştı | Orta | **Kapatıldı**: `test_config.py::TestOllamaHostRestriction` (17 test) eklendi; §2 kanıt satırı düzeltildi |
| B2: Migration testinde analyses tablosu explicit assert yok | Düşük | **Kapatıldı**: `test_upgrade_head_creates_analyses_table` (23 sütun + FK + 3 CHECK) ve `test_downgrade_drops_analyses_before_events` eklendi |
| B3: Değişiklikler commit edilmemiş | Düşük | Bu commit ile kapatılıyor (Faz 04 commit'i) |
| B4: requires_human_review sqlite 0/1; duration_ms son deneme süresi | Bilgi | Kabul edildi; Faz 05 panel dönüşümü notu |
| B5: Mock ölçümler gerçek modeli temsil etmez | Bilgi | §3 uyarısı + Faz 09 holdout ölçümü zorunlu |

Bulgu kapatma sonrası nihai koşum: **281 passed, ruff temiz, mypy temiz**.

## 8. Sonraki küçük adım

Faz 05 — Güvenlik paneli: Auth/RBAC (viewer/analyst/admin), olay listesi/detayı,
filtreler, AI değerlendirmesi gösterimi (ai_assessment ayrı kart; orijinal severity
ayrı), hata/boş/loading durumları.
