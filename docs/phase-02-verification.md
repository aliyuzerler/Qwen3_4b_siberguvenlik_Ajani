# Faz 02 — Wazuh Bağlantısı Doğrulama Raporu

**Tarih:** 2026-10-27
**Yöntem:** `phases/02-wazuh-integration.md` geliştirme promptu uygulandı; ardından
`TEST-PROMPT-TEMPLATE.md` temelinde **bağımsız doğrulayıcı** (taze bağlam, kod
yazma yetkisi olmayan ajan) matrisi koştu ve bu rapor onun çıktısıyla birleştirildi.

## API Kanıtı (uydurma endpoint yasağı — faz kuralı)

- Resmi Wazuh spec'i (`api/api/spec/spec.yaml`, wazuh/wazuh) incelendi: **Server
  API'de (55000) alert OKUMA endpoint'i yoktur.** Alert/olay ile ilgili tek uç
  nokta `POST /events`'tir (ingest — yazma; ajant KULLANMAZ).
- Alert'lerin resmi kaynağı **Wazuh Indexer** (OpenSearch, 9200),
  `wazuh-alerts-*` indeksidir. En az ayrıcalık: indekste yalnızca **read**
  izinli ayrı servis hesabı (`docs/wazuh-staging.md` §1).
- Adapter bu nedenle Indexer `_search` tabanlıdır; yalnızca `GET /` (health)
  ve `POST /wazuh-alerts-*/_search` çağırır (OKUMA; indeks mutasyonu yapmaz).

## Doğrulama Matrisi (bağımsız doğrulayıcı çıktısı)

| # | Test | Beklenen | Gerçek Sonuç | Durum |
|---|------|----------|--------------|-------|
| 1 | `pytest tests/ -q` | Tümü geçer | 58 passed, 0 failed (0.25s) | **PASS** |
| 2 | `ruff check .` | Temiz | All checks passed | **PASS** |
| 3 | `mypy app` | Temiz | 22 kaynak dosya, 0 hata | **PASS** |
| 4 | Salt-okunur kanıtı | Yalnızca GET / ve POST _search | İki çağrı noktası (indexer_source.py:114,142); DELETE/PUT/yazma yolu yok; whitelist testi var | **PASS** |
| 5 | 401/403 → AuthError, tekrarsız | Tek çağrı | test_401: calls==[1], sleep==[] | **PASS** |
| 6 | 429 + Retry-After | Saygı + tavan (15s) + tükenme | delays==[2.0]; cap testi PASS | **PASS** |
| 7 | 5xx | Sınırlı retry → Unavailable | 2 çağrı + 1 backoff | **PASS** |
| 8 | Timeout | Unavailable | PASS | **PASS** |
| 9 | Bağlantı kesintisi | Unavailable + sızıntı yok | PASS | **PASS** |
| 10 | Bozuk JSON | BadPayload, tekrarsız | calls==[1] | **PASS** |
| 11 | Bozuk hit (eksik alan) | BadPayload + alan adı | "rule.level" mesajda | **PASS** |
| 12 | Credential log/mesajda yok | Sıfır sızıntı | 4 test + bağımsız log taraması temiz | **PASS** |
| 13 | Zorunlu alan koruması | id/timestamp/agent/rule/level | parsing._require + raw korunur | **PASS** |
| 14 | Orijinal severity ayrımı | LLM yazma riski yok (Faz 04'te ayrı) | rule_level kanonik int; yazıcı yol yok | **PASS** |
| 15 | Sayfalama + zaman penceresi | from/size + timestamp range | Body assert'li test PASS | **PASS** |
| 16 | Bağlantı durumu / son kontrol | /ready bileşen durumu | up/down/not_configured + tracker | **PASS** |
| 17 | .env / credential repoda değil | Temiz | git ls-files boş; .gitignore kapsıyor | **PASS** |
| 18 | Canlı smoke (mock mod) | /health + /ready 200 | `wazuh:up` (mock), database:up | **PASS** |
| 19 | docker compose up | Dağıtım doğrulaması | Sandbox'ta Docker yok — kullanıcı makinesi | **NOT RUN** |
| 20 | Gerçek Wazuh Indexer (staging) | docs/wazuh-staging.md adımları | Sandbox'ta Wazuh yok | **BLOCKED** |
| 21 | Gerçek PostgreSQL migration | alembic upgrade | Sandbox'ta PG yok (bu fazda migration yok) | **NOT RUN** |

## Yapılan Değişiklikler

- **Yeni**: `app/services/wazuh/` — errors, models (DTO + UTC normalizasyonu),
  parsing (OpenSearch hit → DTO, zorunlu alan koruması), resilience (async
  circuit breaker + sınırlı retry + Retry-After tavanı), status tracker,
  indexer_source (salt okunur istemci), mock_source (hata enjeksiyonlu),
  source (Protocol + fabrika), sentetik fixture (6 alert, RFC 5737 IP'ler).
- **Güncellendi**: config (Wazuh indexer alanları + prod'da mock yasağı),
  main.py (kaynak + tracker kablolama, kapanışta aclose), health.py
  (/ready Wazuh bileşeni), .env.example, log redaction anahtarları.
- **Testler**: 33 mevcut + 25 yeni = 58 (sözleşme 17, mock 6, resilience 10,
  models 7, redaction 2, config/health artışları).
- **Doküman**: `docs/wazuh-staging.md` (salt okunur hesap kurulumu + saha
  doğrulama komutları + `PUT _settings` 403 kanıtı beklenir).

## Güvenlik Etkisi

- Adapter yazma/müdahale yetkisi hiçbir yolda içermiyor (Faz 07'ye kadar kural).
- Credential yalnızca httpx `auth` param'ında; URL'e gömülmez, hata
  mesajlarına ve loglara yazılmaz (testle doğrulanmış).
- Prod modda `WAZUH_SOURCE_MODE=mock` config validator tarafından reddedilir.
- `/ready` Wazuh "down" olsa da 200 döner (panel ayrıca gösterir); servis
  kesintisi CircuitBreaker ile hızlı başarısızlığa döner.

## Kalan Riskler / Sonraki Adım

- **NOT RUN/BLOCKED (saha)**: staging doğrulaması `docs/wazuh-staging.md` §3
  ile yapılmalı; özellikle `PUT _settings` → 403 kanıtı beklenir.
- Breaker half-open penceresinde single-flight yok (çok istek geçebilir);
  Faz 03 worker'da gözden geçirilecek (düşük risk).
- Retry-After yalnızca saniye biçimini okur; HTTP-date üstel backoff'a düşer
  (Wazuh/OpenSearch pratikte saniye kullanır).
- `WazuhNotConfiguredError` şu an fırlatılmıyor (API yüzeyi; Faz 03'te
  `build_alert_source(None)` yolu için kullanılacak).
- Sonraki faz: **Faz 03 — Normalizasyon ve Depolama** (Wazuh veri sözleşmesi,
  ORM + Alembic migration, idempotent alert saklama; son senkronizasyon DB'ye).

**Önerilen Faz 02 durumu: PASS** (18/21 PASS, 3 NOT RUN/BLOCKED — sandbox
kısıtı; kabul ölçütlerini engellemiyor).
