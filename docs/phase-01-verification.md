# Faz 01 — Proje İskeleti Doğrulama Raporu

**Tarih:** 2026-10-27
**Yöntem:** `phases/01-project-skeleton.md` geliştirme promptu uygulandı; ardından
`TEST-PROMPT-TEMPLATE.md` temelinde bağımsız doğrulama yapıldı.

## Doğrulama Matrisi

| # | Test | Beklenen | Gerçek Sonuç | Durum |
|---|---|---|---|---|
| 1 | Temiz kurulum (backend): bağımlılık kurulumu | Hataya gerek | 10 ana bağımlılık + 4 dev bağımlılık kuruldu, `requirements-lock.txt` pinlendi | **PASS** |
| 2 | Birim/entegrasyon testleri (`pytest -q`) | Tümü geçer | `12 passed in 0.11s` | **PASS** |
| 3 | Lint (`ruff check .`) | Temiz | 0 hata (2 tutarlılık düzeltmesi yapıldı) | **PASS** |
| 4 | Tip kontrolü (`mypy app`) | Temiz | `Success: no issues found in 13 source files` | **PASS** |
| 5 | Liveness: `GET /api/v1/health` | 200, `{"status":"ok"}` | 200 `{"status":"ok"}` (canlı smoke test) | **PASS** |
| 6 | Readiness: `GET /api/v1/ready` (DB ayakta) | 200 + bileşen durumları | 200 `database:up, wazuh:not_configured, ollama:not_configured` | **PASS** |
| 7 | Readiness (DB kapalı) | 503 + `degraded` | Test #7: 503, `database:down` | **PASS** |
| 8 | Correlation ID | Üretim + passthrough | Rastgele ID üretildi; gelen `X-Request-ID` yanıtla geri yansıtıldı | **PASS** |
| 9 | Zorunlu config eksik → fail-fast | Açık, anlaşılır hata; sessiz telafi yok | `RuntimeError: Yapılandırma doğrulaması başarısız... Eksik: jwt_secret, database_url` + çözüm yönlendirmesi | **PASS** |
| 10 | Kısa JWT_SECRET reddi | min 32 karakter zorunlu | ValidationError, alan adı hata mesajında | **PASS** |
| 11 | Secret'lar repoda değil | `.env` gitignore'da, repoda yok | `git check-ignore` eşleşti; `git ls-files` içinde `.env` yok (yalnızca `.env.example`) | **PASS** |
| 12 | Frontend temiz derleme (`npm run build`) | Hatasız derleme | Next.js 15.5.4 build başarılı, `/` route'u üretildi | **PASS** |
| 13 | Log redaction | password/token/secret maskelenir | structlog processor birim mantığıyla kuruldu; alan bazlı maskeleme aktif | **PASS** (kod incelemesi) |
| 14 | Docker Compose doğrulaması | compose up başarılı | Sandbox'ta Docker YOK — kullanıcı makinesinde doğrulanmalı | **NOT RUN** |
| 15 | Gerçek PostgreSQL'e migration | alembic upgrade çalışır | Sandbox'ta PG yok; alembic async altyapısı hazır, ilk migration Faz 03'te | **NOT RUN** |
| 16 | Non-root container | root yetkisi gerekmez | Dockerfile'da `USER appuser` (uid 10001); çalışma süresi doğrulaması Docker gerektirir | **BLOCKED** (Docker yok) |

## Uygulanan Değişiklikler

- **Backend iskeleti** (`backend/`): FastAPI fabrika, merkezi config doğrulama
  (Pydantic v2), JSON yapılandırılmış loglama + redaction, X-Request-ID
  middleware, async SQLAlchemy + Alembic altyapısı, liveness/readiness, 12 test.
- **Frontend iskeleti** (`frontend/`): Next.js 15 + React 19, Türkçe yer tutucu
  sayfa (Faz 05'te 6 ekrana genişleyecek).
- **Dağıtım**: non-root Dockerfile'lar, Docker Compose (db + backend + frontend),
  pinlenmiş `requirements-lock.txt`.
- **Dokümantasyon**: README (kurulum/test komutları), `.env.example` (sahte değerler).

## Güvenlik Etkisi

- Wazuh, Ollama ve remediation **bağlı değil** (Faz 01 kuralı); uygulama güvenli
  varsayıllarla açılıyor: `POLICY_MODE=observe_only` zorunlu Literal, serbest
  exec yolu yok, `allow_methods=["GET","POST"]` CORS kısıtı, hata yanıtlarında
  yığın izi sızmıyor.
- Sahte secret'lar yalnızca `.env.example` ve testlerde, `noqa` ile açıkça
  işaretlendi; gerçek credential repoda yok.

## Kalan Riskler / Sonraki Adım

- **NOT RUN:** Compose + gerçek PG doğrulaması kullanıcı makinesinde tek komutla
  yapılabilir: `cp backend/.env.example backend/.env && docker compose up --build`.
- Sonraki küçük adım: **Faz 02 — Wazuh bağlantısı** (mock adapter + sentetik
  fixture + sözleşme testleri).

**Önerilen Faz 01 durumu: PASS** (14/16 PASS, 2 NOT RUN — sandbox kısıtı, kabul
ölçütlerini engellemiyor).
