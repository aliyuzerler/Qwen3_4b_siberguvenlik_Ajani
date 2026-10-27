# ajant — Dağıtım ve Operasyon Runbook'u (Faz 10)

Kapsam: `phases/10-deployment-and-operations.md` — "Staging'de doğrulanan sürüm
için dağıtım belgeleri ve operasyon runbook'u". Bu belge **başka bir operatörün
baştan sona izleyebileceği tek akıştır**: temiz makine → doğrulanmış staging.

Belge zinciri (bu runbook bunlara dayanır, tekrar etmez):
- `docs/deployment.md` (Faz 08) — sertleştirme ayrıntıları: TLS, güvenlik duvarı,
  log rotation, secret yönetimi derinlik, non-root yetkiler.
- `docs/wazuh-staging.md` (Faz 02) — Wazuh Indexer salt okunur hesap kurulumu.
- `docs/incident-runbook.md` (Faz 08) — 9 olay senaryosu müdahalesi.
- `docs/remediation-runbook.md` (Faz 07) — kill switch, aksiyon rollback/mitigation.
- `docs/phase-09-benchmark.md` — model değerlendirme ve NOT RUN komutları.

İlke (phases/10): **Üretim ortamına otomatik dağıtım YOKTUR** — önce staging
doğrulaması ve kullanıcı onayı. Bu depoda otomatik dağıtım pipeline'ı bilinçli
bulunmaz (yol haritası: docs/deployment.md §12).

---

## 1. Ön koşullar ve sürüm sabitleme

| Bileşen | Sabit sürüm | Doğrulama komutu | Not |
|---|---|---|---|
| Docker Engine | 24+ (Compose v2) | `docker compose version` | compose dosyası v2 sözdizimi |
| Ollama | 0.5+ | `ollama --version` | yalnızca host'ta; compose içinde KOŞMAZ |
| Model | **`qwen3:4b`** (tag SABİT) | `ollama list` | q4_K_M quantization varsayılanı |
| Python (backend imajı) | 3.12-slim-bookworm | `docker compose run --rm backend python --version` | Dockerfile pinli |
| PostgreSQL | 16-alpine | `docker compose exec db psql --version` | compose pinli |
| Node (frontend imajı) | 22-alpine | `docker compose exec frontend node --version` | Dockerfile pinli |
| Backend bağımlılıkları | `requirements-lock.txt` | `pip-audit -r backend/requirements-lock.txt` | pinli: fastapi 0.162.0, pydantic 2.12.5, pydantic-settings 2.14.2, starlette 1.3.1, PyJWT 2.15.1, alembic 1.20.1, uvicorn 0.44.0, httpx 0.28.1, structlog 25.5.0, asyncpg 0.32.0 |
| Frontend bağımlılıkları | `package-lock.json` | `cd frontend && npm audit` | pinli: next 15.5.28, react 19.1.0 |
| Uygulama sürümü | git tag / commit | `git describe --tags` | staging = doğrulanan commit |

**Kurallar:**
- Model tag `qwen3:4b` konfigürasyonda sabittir (`OLLAMA_MODEL_TAG`); başka tag
  ile başlatım `/ready`'de `model_missing` üretir (istenen davranış).
- Bağımlılık yükseltmesi yalnızca güvenlik gerekçesiyle ve her adımda tam test
  ile yapılır (Faz 08'deki fix zinciri: docs/deployment.md §10).
- İmaj digest pinleme staging doğrulamasından SONRA yapılır
  (docs/deployment.md §10 — `python:3.12-slim-bookworm@sha256:…`).

Donanım ön koşulu: 32 GB RAM (model CPU modunda çalışır; qwen3:4b q4_K_M
~3 GB çip belleği + işletim sistemi payı), 20 GB+ boş disk (imaj + model + pgdata).

## 2. Kurulum akışı (temiz makineden doğrulanmış staging'e)

Her adımın **beklenen çıktısı** yazılıdır; bir adım bekleneni vermezse sonraki
adıma GEÇİLMEZ (sessiz yarım kurulum yoktur — migration hatası konteyneri düşürür).

**A) Depoyu al ve sürümü sabitle**

```bash
git clone https://github.com/aliyuzerler/ajant.git ajant && cd ajant
git checkout <doğrulanan-commit-veya-tag>
```

**B) Backend env hazırla** (zorunlu alanlar tablosu):

```bash
cp backend/.env.example backend/.env
chmod 600 backend/.env
$EDITOR backend/.env
```

| Değişken | Zorunlu | Üretim notu |
|---|---|---|
| `JWT_SECRET` | EVET | `openssl rand -hex 32` (≥32 karakter) |
| `ADMIN_BOOTSTRAP_PASSWORD` | EVET | ≥12 karakter; **ilk girişten sonra değiştir** (§2-G) |
| `WAZUH_SOURCE_MODE` | EVET | `indexer` (üretim; `mock` prod'da uygulama BAŞLAMAZ) |
| `WAZUH_INDEXER_URL/USER/PASSWORD` | EVET | docs/wazuh-staging.md §1-2 (salt okunur hesap) |
| `WAZUH_VERIFY_TLS` | EVET | üretimde `true`; `false` iken prod başlamaz |
| `OLLAMA_BASE_URL` | EVET | compose: `http://host.docker.internal:11434` |
| `POLICY_MODE` | EVET | `observe_only` (üretimde zorunlu; dry_run ekstra anahtar ister) |
| `WORKER_LOOP_ENABLED` | opsiyonel | `true` = otomatik ingest+analiz döngüsü; varsayılan `false` (güvenli başlangıç) |
| `RATE_LIMIT_BACKEND` | opsiyonel | çok prosesli backend'de `database` (deployment.md §2.1) |
| `APP_ENV` | EVET | `prod` → /docs+openapi kapalı, prod validator'lar aktif |

**C) Compose parolasını değiştir** — `docker-compose.yml` içindeki
`SAHTE_YEREL_PAROLA_DEGISTIR` (db + backend `DATABASE_URL`) gerçek parolayla
değiştirilir; `.env` ile TUTARLI olmalıdır (compose `environment` override eder).

**D) Ollama + model kurulumu** — ayrıntı §3.

**E) Stack'i başlat** (backend başlangıcında `alembic upgrade head` otomatik):

```bash
docker compose up -d --build
docker compose ps        # beklenen: 3 servis "running/healthy"
```

**F) Migration ve health doğrulaması:**

```bash
docker compose logs backend | grep alembic   # beklenen: "Running upgrade ... -> 0006"
curl -s http://127.0.0.1:8000/api/v1/health  # {"status":"ok"}
curl -s http://127.0.0.1:8000/api/v1/ready | python3 -m json.tool
# beklenen: database=up; wazuh=up (kurulduysa); ollama=up (§3 sonrası); disk=up
```

**G) Admin girişi ve parola değişimi:**

```bash
# Panel: http://127.0.0.1:3000 → kullanıcı: admin / ADMIN_BOOTSTRAP_PASSWORD
```

İlk giriş `users` tablosu boşken bootstrap hesabı oluşturur (parola log/yanıta
yansıtılmaz). **Hemen `Hesabım` sayfasından parolayı değiştirin** — bootstrap
parolası `users` DOLU olduktan sonra işlemez (güvenlik) ama env'de kalması
risktir: ilk değişimden sonra `ADMIN_BOOTSTRAP_PASSWORD` satırını `.env`'den
SİLİN.

**H) Test alert besleme (staging; gerçek Wazuh yokken):**

```bash
# gerçek Wazuh YOK: sentetik, ŞİMDİ damgalı 6 alert (üretim ingest yoluyla)
DATABASE_URL="postgresql+asyncpg://ajant:<parola>@127.0.0.1:5432/ajant" \
  python3 scripts/seed_staging_events.py
# beklenen tek satır JSON: {"fetched":6,"stored":6,"duplicate":0,"variant":0,"failed":0}
# tekrar koşum: {"stored":0, ...} — YENİ SATIR ÜRETMEZ (idempotent)
```

Not: `seed_staging_events.py` alembic şeması UYGULANMIŞ bir DB ister (compose
başlangıcında otomatik uygulanır). Gerçek Wazuh bağlıysa bu adım ATLANIR —
alert'ler §4 doğrulamasından sonra worker ingest'le gelir.

**I) AI analizi doğrulaması** — `backend/.env`:

```env
WORKER_LOOP_ENABLED=true
ANALYSIS_ENABLED=true
```

```bash
docker compose up -d backend   # env yeniden yükle
sleep 40                        # WORKER_INTERVAL_SECONDS=30 ilk tur
docker compose logs backend | grep worker_analysis_cycle
# beklenen: pending>0, completed>0 (gerçek model yanıtları) — VEYA
#           analysis_failed satırları (çıktı geçersizse; güvenli fallback)
curl -s -H "Authorization: Bearer <token>" http://127.0.0.1:8000/api/v1/events | \
  python3 -c 'import json,sys; [print(i["alert_id"], i["analysis"]["status"] if i["analysis"] else "pending") for i in json.load(sys.stdin)["items"]]'
```

**J) Panel uçtan uca doğrulaması** (tarayıcı, `http://127.0.0.1:3000`):
1. Giriş → Genel bakış: bileşen kartları (`/ready` ile tutarlı), sayaçlar.
2. Olaylar: 6 sentetik olay, filtreler (değerlendirme/rule_level/arama) çalışır.
3. Olay detayı: orijinal kanıt + AI değerlendirmesi AYRI bölümlerde
   (severity asla üzerine yazılmaz — `ai_assessment` ayrı alan).
4. Kullanıcılar (admin): viewer/analyst hesabı oluştur, rol kısıtlarını doğrula.
5. Çıkış → viewer ile giriş: yönetici sayfaları 403/görünmez olmalı.

## 3. Ollama kurulumu ve doğrulaması (host makinede)

```bash
# 1) Kurulum (Debian/Ubuntu resmi script) — kurum politikasına göre paketleşin
curl -fsSL https://ollama.com/install.sh | sh
systemctl enable --now ollama

# 2) Yalnızca loopback'e bağla (dış dünyaya KAPALI — deployment.md §4)
systemctl edit ollama
#   [Service]
#   Environment="OLLAMA_HOST=127.0.0.1:11434"
systemctl restart ollama
ss -tlnp | grep 11434     # beklenen: 127.0.0.1:11434 (0.0.0.0 DEĞİL!)

# 3) Model indir ve doğrula (tag sabit: qwen3:4b)
ollama pull qwen3:4b      # ~2.5 GB (q4_K_M)
ollama list               # beklenen: qwen3:4b satırı
ollama show qwen3:4b      # parametreler + quantization künyesi

# 4) Üretim testi (JSON disiplini — model ısıtması da olur)
ollama run qwen3:4b 'Yalnızca JSON döndür: {"risk":"low","reason":"test"}'

# 5) Bellek yoklaması (CPU modu)
ollama ps                 # model yüklüyken total_size + %CPU görülmeli

# 6) Host bağlantı doğrulaması
curl -s http://127.0.0.1:11434/api/version

# 7) Konteyner → host bağlantı doğrulaması (compose extra_hosts sayesinde)
docker compose exec backend python -c \
  "import urllib.request; print(urllib.request.urlopen('http://host.docker.internal:11434/api/version', timeout=3).read()[:60])"
```

Ardından **F adımındaki `/ready`** çağrısında `ollama: "up"` beklenir:
- `model_missing` → `ollama pull qwen3:4b` + backend'i yeniden başlatmak gerekmez
  (probe anlık kontrol eder), model inince `up` olur.
- `down` → OLLAMA_BASE_URL host.docker.internal mi? güvenlik duvarı 11434'ü
  docker bridge'e kapattı mı? (deployment.md §4 firewall önerileri)
- Opsiyonel derin doğrulama (Faz 09 CLI, gerçek model koşumu):

```bash
cd backend
python -m benchmarks.cli check --base-url http://127.0.0.1:11434   # exit 0 beklenir
python -m benchmarks.cli run --llm ollama --baseline qwen_prompt_only ...
# ayrıntılı komutlar: docs/phase-09-benchmark.md §6
```

**Güvenlik kuralı:** `OLLAMA_ALLOW_PUBLIC_HOST=false` (varsayılan) genel
FQDN/IP'yi config validator'ı ile REDDEDER — Ollama'yı asla internete açmayın;
model erişimi yalnızca loopback/docker bridge üzerinden verilir.

## 4. Wazuh bağlantısı (staging)

Uçtan uca talimat: **docs/wazuh-staging.md** (salt okunur `ajant-readonly`
servis hesabı → `ajant_readonly` rolü → `wazuh-alerts*` read izni → role
mapping). Sıralı doğrulama:

```bash
# 1) Okuma yetkisi: 200 + hit alanları
curl -sk -u ajant-readonly:'<parola>' -H 'Content-Type: application/json' \
  -X POST "https://<indexer>:9200/wazuh-alerts-*/_search" \
  -d '{"size":1,"sort":[{"timestamp":{"order":"desc"}}]}' | head
# 2) Yazma ENGELİ: beklenen 403 (salt okunur kanıtı)
curl -sk -u ajant-readonly:'<parola>' -X PUT \
  "https://<indexer>:9200/wazuh-alerts-*/_settings" -d '{}' | head
# 3) Uygulama: /ready wazuh=up
curl -s http://127.0.0.1:8000/api/v1/ready | grep wazuh
```

`WAZUH_VERIFY_TLS=false` YALNIZCA self-signed staging'de geçicidir; prod'da
`false` iken uygulama BAŞLAMAZ (config validator). Bağlantı kurulunca worker
döngüsü (§2-I) alert'leri `wazuh-alerts-*`'ten sayfalayıp idempotent saklar;
kesinti sonrası cursor'dan KALDIĞI YERDEN devam eder (idempotent yeniden çekim —
loop.py cursor disiplini).

## 5. Health check ve smoke test

**Liveness vs readiness ayrımı:** `/api/v1/health` süreç canlı mı (bağımlılık
bakmaz); `/api/v1/ready` DB+Wazuh+Ollama+disk bileşen durumları (yalnız DB down
503'tür; diğerleri 200 + bileşen durumu — kesinti ≠ panel çökmesi).

**Bileşen durum tablosu:**

| Bileşen | Durumlar | Anlam |
|---|---|---|
| database | up / down | down → 503 + panel hata (runbook §2) |
| wazuh | up / down / not_configured | not_configured = kaynak yok (boş indexer env) |
| ollama | up / down / model_missing / disabled / not_configured | disabled = ANALYSIS_ENABLED=false (kill switch) |
| disk | up / low_space / unknown | low_space = DISK_MIN_FREE_PERCENT altı (503 DEĞİL, uyarı) |

**Sandbox sözleşme smoke'u** (Docker/Ollama'sız; 33 kontrol, 7 evre):

```bash
bash scripts/phase10_smoke.sh
# beklenen: FAZ 10 SMOKE SONUCU: 33 PASS, 0 FAIL (exit 0)
```

Kapsam: temiz kurulum+health → sentetik besleme (idempotent) → model kesik
(pending korunur, sahte değerlendirme YOK, döngü yaşar) → bozuk model çıktısı
(analysis_failed fallback) → Wazuh kesintisi (zarif düşüş) → kill switch →
backup/restore script sözleşmesi. **Staging'de** ayrıca Faz 08 güvenlik smoke'u:

```bash
bash scripts/phase08_smoke.sh   # 39/39 PASS (başlıklar, 413, kullanıcı akışları, frenler, prod matrisi)
```

## 6. Test alert → AI analizi (uçtan uca senaryolar)

| Senaryo | Nasıl | Beklenen |
|---|---|---|
| Normal analiz (gerçek model) | §2-H besle + §2-I worker açık | `completed` + kanıt/öneri alanları; severity orijinal değer kalır |
| Ollama KESİK | `systemctl stop ollama` → yeni alert besle → tur bekle | satır YAZILMAZ, event pending kalır; döngü `worker_cycle_failed` loglar ve YAŞAR; Ollama dönünce otomatik analiz |
| Model BOZUK çıktı üretiyor | `python3 scripts/fake_ollama_server.py --port 11450` + `OLLAMA_BASE_URL=http://127.0.0.1:11450 docker compose up -d backend` | `/ready` ollama=up; her event `analysis_failed` satırı (retry tükenir); uydurma completed YOK |
| Kill switch | `ANALYSIS_ENABLED=false` + restart | `/ready` ollama=disabled; Ollama'ya çağrı YAPILMAZ |

**KANIT UYARISI:** `fake_ollama_server.py` bir TEST DÜZENEĞİDİR — çıktıları
model kalitesi kanıtı SAYILMAZ (Faz 09'daki `results_valid_as_model_evidence=false`
aynı disiplin). Gerçek model ölçümü yalnızca benchmark CLI + gerçek Ollama ile.

Sentez veri uyarısı: `seed_staging_events.py` yalnızca staging/test DB'sinde
koşulur; üretim DB'sine sentetik alert bulaştırma YASAK.

## 7. İzleme ve alarm eşikleri

`/ready` bileşenlerini tarama cron'u ve `alert-ajant.sh` örneği:
docs/deployment.md §6. Eşik/aksiyon tablosu:

| Sinyal | Kaynak | Eşik/koşul | Operatör aksiyonu |
|---|---|---|---|
| `database: down` | /ready | anında (503) | incident-runbook §2 (db konteyner/restore) |
| `wazuh: down` | /ready | 15 dk sürerse | §4 doğrulama; breaker 30 sn'de bir yeniden dener; cursor güvenli |
| `ollama: down/model_missing` | /ready | 30 dk sürerse | incident-runbook §6 (servis + pull) |
| `disk: low_space` | /ready | eşik DISK_MIN_FREE_PERCENT (10) | incident-runbook §1 temizlik |
| `auth.login.failed` patlaması | audit | IP başına >50/saat | incident-runbook §3 (brute force) |
| 429 oranı artışı | backend log | kalıcı >%5 istek | AUTH/REM tavanlarını gözden geçir |
| `analysis_failed` oranı | `worker_analysis_metrics` log | >%50 sürekli 1 saat | model tag/Ollama log; benchmark §6 |
| analiz p95 | aynı log | >10 s (Faz 09 tetikleyici) | CPU/RAM, WORKER_CONCURRENCY |
| pgdata büyümesi | cron `df` | +%5/hafta | RETENTION_DAYS gözden geçir |
| schema_valid_rate | aynı log | <0.90 (Faz 09 tetikleyici) | model sürümü değişti mi? prompt sürümü? |

Log kaynakları: structlog JSON stdout (konteyner log rotasyonu 10m×3 —
deployment.md §5); metrikler `worker_analysis_metrics` satırlarında
(schema_valid_rate, p50, p95, error_rate).

## 8. Güvenli davranış: bağımlılık kesintileri matrisi

| Kesinti | /ready | Panel | Ingest | Analiz | Kanıt |
|---|---|---|---|---|---|
| DB down | 503 | hata sayfası | durur | durur | health.py (yalnız DB 503) |
| Wazuh down | 200 + down | bileşen kartı kırmızı; SAKLI olaylara erişim SÜRER | DURUR (cursor korunur) | bekleyen pending'ler analiz edilir | smoke Evre 5; loop.py hata izolasyonu |
| Ollama down | 200 + down | kart; pending sayısı | çalışır | PENDING KALIR — sahte değerlendirme YAZILMAZ | smoke Evre 3; analysis.py "altyapı hatası satır yazmaz" |
| Model bozuk çıktı | 200 + up | `analysis_failed` etiketli olaylar | çalışır | analysis_failed SATIRI (güvenli fallback) | smoke Evre 4; analyzer.py çıktı ailesi |
| ANALYSIS_ENABLED=false | disabled | kart "disabled" | çalışır | Ollama'ya ÇAĞRI YOK | smoke Evre 6 |
| Disk doluyor | low_space | uyarı kartı | çalışır | çalışır | health.py disk bileşeni |

Temel garanti (AGENTS.md §4-5): model/Wazuh erişimi kesildiğinde sistem
**yalnızca gözlemi durdurur, asla uydurma veri üretmez**; audit ve saklı olaylar
dokunulmaz kalır.

## 9. Upgrade ve rollback (operatör checklist)

**Upgrade** (deployment.md §8 genişletme):

1. `./scripts/backup_db.sh ./backups --prune-days 30` — ÖNCE yedek (TAMAM çıktısı zorunlu)
2. `git fetch && git checkout <yeni-sürüm>` (release notes/verification belgesi oku)
3. `docker compose build && docker compose up -d`
4. `docker compose logs backend | grep alembic` — migration beklentisi
5. `/health` + `/ready` + panel girişi + bir test alert akışı (§6)
6. Sorun 24 saat gözlemlenmeden "başarılı" denmez (analiz metriklerine bak)

**Rollback** (deployment.md §9 + incident-runbook §7):

```bash
./scripts/backup_db.sh ./backups            # MEVCUT durumu yedekle (adli kopya)
docker compose stop backend
git checkout <önceki-tag>
docker compose run --rm backend alembic downgrade <hedef-revision>  # yalnızca şema farkı varsa
docker compose up -d --build
curl -s http://127.0.0.1:8000/api/v1/ready  # bileşenler up
```

- Veri bozulması şüphesi: `restore_db.sh` (YIKICI — onay ister; §10 bakım).
- Uygulama modu rollback'i: `POLICY_MODE=observe_only` her zaman güvenli liman;
  kill switch'ler `REMEDIATION_ENABLED/ANALYSIS_ENABLED/CORRELATION_ENABLED=false`.

## 10. Backup / restore ve bakım takvimi

Yedek/restore prosedürü: deployment.md §7 (`backup_db.sh` — pg_dump custom
format + sıfır-bayt koruması + `pg_restore -l` archive doğrulaması + **Faz 10
sertleştirmesi: başarısız koşumda yarım dump otomatik SİLİNİR (EXIT trap)**;
`restore_db.sh` — onay sorar, backend'i durdurur, `--clean --if-exists` restore).

| Periyot | Görev | Komut/bağlantı |
|---|---|---|
| Günlük (cron) | yedek + prune | `backup_db.sh ./backups --prune-days 30` |
| Günlük (cron) | /ready bileşen taraması + disk | deployment.md §6 cron |
| Haftalık | yedek bütünlük turu | `pg_restore -l <son-dump>` exit 0 |
| Haftalık | secret taraması | `./scripts/secret_scan.sh` |
| Aylık | restore testi (staging) | deployment.md §7 restore akışı |
| Aylık | dependency taramaları | pip-audit + npm audit (§10 deployment.md) |
| Aylık | audit log gözden geçirme | panel /audit; anomali senaryoları incident-runbook §9 |
| 6 aylık | TLS sertifikası + parola rotasyonu | deployment.md §3-4 |
| 6 aylık | sürüm yükseltme planı | §9 upgrade checklist |

Bakım penceresi disiplini: yıkıcı adım (restore/downgrade) ÖNCE yedek, sonra
onay; pencere dışında yıkıcı işlem koşulmaz (incident-runbook ilkesi).

## 11. Faz kabul karşılaştırması (kabul matrisi satır 11 "Dağıtım")

| Ölçüt | Durum | Kanıt |
|---|---|---|
| Staging doğrulaması | sözleşme düzeyi KANITLI; gerçek staging koşumu kullanıcı makinesi | §2 akışı (A-J beklenen çıktılı), phase10_smoke 33/33, phase08_smoke 39/39; NOT RUN §12 |
| Backup | KANITLI (script sözleşmesi) | backup_db.sh (trap sertleştirmesi dahil) + restore_db.sh onay/argüman koruması; smoke Evre 7 |
| Monitoring | KANITLI | §7 eşik tablosu, /ready 4 bileşen, cron örnekleri, Faz 09 tetikleyici bağlantısı |
| Rollback planı | KANITLI | §9 checklist + deployment.md §9 + incident-runbook §7 |
| Dokümantasyon ve runbook | KANITLI | bu belge + deployment.md + incident-runbook.md + remediation-runbook.md + wazuh-staging.md zinciri |

## 12. NOT RUN (sandbox kısıtı) — kullanıcı makinesi komutları

Sandbox'ta Docker, gerçek Ollama ve gerçek Wazuh yoktur. Aşağıdaki koşumlar
staging makinesinde sırayla yapılmalıdır (her komutun beklenen çıktısı §2-§6'da):

```bash
# 1) Stack canlı kurulum + migration (§2-E/F)
docker compose up -d --build
docker compose logs backend | grep alembic
curl -s http://127.0.0.1:8000/api/v1/ready

# 2) Gerçek model uçtan uca (§2-D/§3)
ollama pull qwen3:4b && curl -s http://127.0.0.1:8000/api/v1/ready | grep ollama
# §2-H/I: seed_staging_events.py + WORKER_LOOP_ENABLED=true → completed beklenir

# 3) Gerçek Wazuh ingest (§4; docs/wazuh-staging.md)
# indexer .env → /ready wazuh=up → worker ingest fetched>0 → panelde olaylar

# 4) Gerçek backup/restore koşumu (§10; deployment.md §7)
./scripts/backup_db.sh ./backups && ./scripts/restore_db.sh backups/<dump>   # evet onayı

# 5) Gerçek model benchmark (Faz 09 açık kalemleriyle birlikte)
cd backend && python -m benchmarks.cli check --base-url http://127.0.0.1:11434

# 6) Yetkili staging'de port taraması + TLS proxy (deployment.md §4)
nmap -sT -p- <staging-ip>   # beklenen: yalnızca 22/443 görünür (8000/3000 loopback)
```

Bu kalemler tamamlanınca `docs/phase-10-verification.md` §staging tablosu
işaretlenir ve kabul satırı 11 tamamlanmış olur.

## 13. Faz 10 dosya listesi

| Dosya | Rol |
|---|---|
| `docs/phase-10-operations.md` | bu runbook (dağıtım + operasyon) |
| `docs/phase-10-verification.md` | gereksinim→kanıt matrisi + NOT RUN |
| `scripts/phase10_smoke.sh` | uçtan uca operasyon smoke (33 kontrol, 7 evre; sandbox) |
| `scripts/fake_ollama_server.py` | bozuk-çıktı model düzeneği (fallback yolu kanıtı; TEST aracı) |
| `scripts/seed_staging_events.py` | sentetik test-alert besleyici (üretim ingest yolu; idempotent) |
| `scripts/backup_db.sh` | Faz 10 sertleştirmesi: EXIT trap (yarım dump kalmaz) |
| `docs/deployment.md` | §7'ye trap notu eklendi |
