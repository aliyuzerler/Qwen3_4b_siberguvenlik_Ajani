# Faz 08 Doğrulama — Güvenlik Sertleştirme ve Dağıtım Hazırlığı

Kapsam: `phases/08-hardening-and-release.md` + kabul satırı 08
("Yetkisiz erişim, injection, rate limit, secret scanning, dependency scan
ve backup/restore testleri") + `phases/TEST-PROMPT-TEMPLATE.md`.

Tüm test verisi SENTETİKTİR (RFC 5737 IP'leri, ÖRNEK parolalar). Bu doküman
geliştirici koşumunu raporlar; bağımsız doğrulayıcı koşumu (worklog
`Task ID: 8-test`) ayrıdır.

---

## 1. Gereksinim → Kanıt matrisi

| Gereksinim (phases/08) | Uygulama | Kanıt |
|---|---|---|
| Non-root servisler | backend `appuser` (uid 10001), frontend `node`; `cap_drop ALL` + `no-new-privileges` + backend `read_only`+tmpfs | Dockerfile'lar + docker-compose.yml; kapsayıcı doğrulaması kullanıcı makinesinde (NOT RUN) |
| Ağ segmentasyonu | compose `frontend_net` + `backend_net (internal: true)`; db yalnızca iç ağ; 8000/3000 yalnızca 127.0.0.1'e bağlanır | docker-compose.yml (statik); compose up doğrulaması NOT RUN |
| Ollama internete açık değil | config host kısıtı (Faz 04; korundu) + compose host-gateway + deployment §1/§4 (`OLLAMA_HOST=127.0.0.1` talimatı) | `test_config.py::TestOllamaHostRestriction` (17 test, değişmedi); smoke 39/39 |
| Wazuh API yalnızca gerekli ağlar | deployment §4 güvenlik duvarı önerileri (9200 kaynak IP kısıtı); salt okunur sözleşme (Faz 02) | doküman; host-fw doğrulaması kullanıcı makinesinde (NOT RUN) |
| TLS ve güvenli cookie/header | SecurityHeadersMiddleware (nosniff/DENY/no-referrer/no-store/CSP); HSTS koşullu; prod'da /docs+redoc+openapi KAPALI; **cookie+CSRF yeniden değerlendirmesi: Bearer-kimlik modeli KORUNDU** (cookie yok → CSRF vektörü uygulanamaz; gerekçe §3.1) | `test_security_headers.py` (7 test); smoke: 6 başlık + HSTS-yok + prod /docs 404 |
| RBAC ve audit | /users uçları admin dependency; 4 yeni AuditAction (user.created/updated/password_changed/password_reset); self-disable, son-admin, self-reset korumaları | `test_users_api.py` (21 test); smoke: viewer 403, anonim 401, self-disable 409, son-admin 409 |
| DB backup/restore testi | scripts/backup_db.sh (pg_dump -Fc, sıfır-bayt koruması, prune) + restore_db.sh (onaylı, --clean); prosedür deployment §7 | sandbox'ta Docker yok → **NOT RUN** (kullanıcı makinesi komutları §5); script mantığı statik incelendi |
| Health check | /health + /ready (db/wazuh/ollama + YENİ disk) | mevcut test paketi + `test_health.py::TestDiskComponent` (4 test) |
| Log rotation | compose json-file max-size/max-file (her servis) + host logrotate örneği (deployment §5) | compose statik; host tarafı NOT RUN |
| Disk dolması alarmı | /ready `disk` bileşeni (up/low_space/unknown); DISK_MIN_FREE_PERCENT; uyarı logu | `TestDiskComponent`; smoke: disk bileşeni raporu |
| Rate limit ve DoS dayanıklılığı | (1) brute-force freni 429+Retry-After; (2) **paylaşımlı depo**: DatabaseRateLimiter (ON CONFLICT UPSERT, rate_limit_counters tablosu, migration 0006); (3) BodySizeLimitMiddleware (413); (4) max_keys tavanı (Faz 05) | `test_db_rate_limit.py` (10 test — iki-instance paylaşım kanıtı); `test_security_headers.py::TestBodySizeLimit` (4); smoke: 429+Retry-After+DB satırları+413 |
| Kurulum/upgrade/rollback dokümantasyonu | docs/deployment.md (kurulum, çok-proses, secret, TLS, log, izleme, backup, upgrade §8, rollback §9, taramalar §10) | doküman |
| Üretime geçişte observe-only varsayılanı | prod validator: `POLICY_MODE != observe_only` → başlangıç RED (escape hatch: REMEDIATION_PROD_ALLOW_DRY_RUN iki kapı); prod CORS localhost RED; prod WAZUH_VERIFY_TLS=false RED | `test_security_headers.py::TestProdHardening` (6 test); smoke Evre C: 3 geçersiz prod config ÇÖKER |
| Secret scanning | scripts/secret_scan.sh (desen taraması + .env git-dışı kontrolü) | koşum: **TEMİZ** (§2) |
| Dependency vulnerability scan | pip-audit + npm audit; BULGULAR KAPATILDI (§2 tablo) | koşum: her iki taraf **0 zafiyet** |
| Yetkisiz erişim testleri | anonim/viewer/analyst RBAC matrisi tüm /users uçlarında; devre dışı kullanıcı token'ı anında 401; pasif hesap login edemez (YENİ — savunma derinliği) | `test_users_api.py::TestUsersRbac`, `TestUpdateUser::test_disabled_user_token_immediately_invalid`; smoke |
| Injection testleri | kalıcı set: prompt injection (Faz 04), input validation `extra=forbid` şemalar (Faz 06/07), username pattern + parola uzunluğu 422 (YENİ) | `test_users_api.py::TestCreateUser`; mevcut injection paketi değişmeden PASS |

## 2. Test promptu kapsamı → sonuç (geliştirici koşumu)

| Senaryo | Sonuç | Kanıt |
|---|---|---|
| secret scanning | **PASS — TEMİZ** | `./scripts/secret_scan.sh`: izlenen dosyalarda secret kalıbı 0; .env git'te izlenmiyor |
| dependency scan (Python) | **PASS — TEMİZ** (başlangıçta 30 bulgu VARDI, kapatıldı ↓) | `pip_audit -r requirements-lock.txt --no-deps` → "No known vulnerabilities found" |
| dependency scan (Node) | **PASS — TEMİZ** (başlangıçta 3 bulgu + kritik RCE, kapatıldı ↓) | `npm audit` → "found 0 vulnerabilities" |
| rate limit (brute-force) | **PASS** | smoke: 3 yanlış giriş sonrası 4. deneme 429 + Retry-After; DB fren modunda 429 + rate_limit_counters satırları DB'de |
| yetkisiz erişim | **PASS** | anonim 401 / viewer 403 / analyst 403 (5 /users ucu); pasif hesap login+token 401; son-admin/self-disable 409 |
| injection | **PASS** | username pattern dışı 4 değer → 422; extra alanlar 422 (extra=forbid); mevcut prompt-injection paketi (Faz 04) değişmeden PASS |
| backup/restore | **NOT RUN** (sandbox'ta Docker/Postgres yok) — komutlar §5; script + prosedür teslim edildi, restore testi kullanıcı makinesinde |
| TLS/sertifika doğrulama | **PASS (uygulama katmanı)** / **NOT RUN (proxy katmanı)** | prod'da WAZUH_VERIFY_TLS=false başlangıç RED (test+smoke); Caddy HSTS örneği deployment §4; proxy kurulumu kullanıcı makinesinde |
| disk dolması simülasyonu | **PASS (birim düzeyi)** / **NOT RUN (gerçek disk doldurma)** | monkeypatch disk_usage → low_space/unknown/up (4 test); gerçek doldurma staging'de |
| rollback | **PASS (kod yolu)** / **NOT RUN (compose ile gerçek geri dönüş)** | migration 0006 upgrade→downgrade→re-upgrade testleri PASS; prosedür deployment §9 |
| port taraması | **NOT RUN** — yalnızca yetkili staging'te yapılır (deployment §4 komutu; compose bağlama stratejisi statik incelendi: 8000/3000 yalnızca 127.0.0.1, 5432 host'ta yok) |

### Dependency bulguları ve kapatma (gerekçe: AGENTS.md §7 + öncelik 1 güvenlik)

| Paket | Bulunan | Kapatma | Doğrulama |
|---|---|---|---|
| PyJWT 2.12.1 | 11 açık (PYSEC-2026-175/176/177/178/179/4140/4141/4144/4145/4147/4148/4149/4152/4183, GHSA-pxh4-856f-4h89) | → 2.15.1 | pytest 592/592 (token akışı dahil) |
| starlette 0.50.0 | 5 açık (PYSEC-2026-161/2280/2281/248/249) | → 1.3.1 | tam paket + canlı smoke 39/39 |
| fastapi 0.128.0 | starlette 1.x uyumu için | → 0.162.0 | tam paket + smoke |
| pydantic-settings 2.13.1 | CVE-2026-58203 | → 2.14.2 | config testleri |
| next 15.5.4 | kritik RCE (GHSA-9qr9-h5gf-34mp) + 30+ açık | → 15.5.28 (patch) | vitest 31/31 + npm build 14 route |
| postcss 8.4.31 (next içi) | XSS + dosya okuma (GHSA-qx2v-qp2m-jg93 vb.) | npm override → 8.5.32 | build + vitest |
| sharp (dev zinciri) | libvips CVE'leri | npm audit fix | `npm audit` → 0 |

**Son durum**: pip-audit "No known vulnerabilities found"; npm audit "found 0
vulnerabilities" (prod + dev ağacı).

**Toplam koşum (geliştirici):**
- Backend: `pytest tests/ -q` → **595 passed, 0 failed** (Faz 07: 534 → +61:
  db_rate_limit 10, users_api 23, security_headers 16 [başlık/HSTS/gövde/
  prod-matris/413-başlık-regresyonu], health-disk 4, migrations-0006 3,
  prod validator testleri dahil) — uyarı: aralıklı 1 non-deterministik
  resource uyarısı gözlemlendi (koşumlardan bazılarında; sonuç etkilenmez)
- `ruff check app tests` → All checks passed; `mypy app` → 77 dosya temiz
- Frontend: `npx vitest run` → **31 passed (7 dosya)** (+8: users 4, hesabim 4);
  `npm run build` → başarılı (**14 route**, +2: /users, /hesabim)
- Canlı smoke: `scripts/phase08_smoke.sh` → **39/39 PASS** (Evre A başlıklar/
  gövde limiti/users akışı/brute-force; Evre B HSTS+DB fren; Evre C prod
  matrisi: /docs 404 + 3 geçersiz prod config çöküşü)
- Alembic: 0001↔0006 roundtrip + 0006 özel upgrade/downgrade/roundtrip testleri
- Log credential taraması: uvicorn smoke logunda SAHTE parola/JWT izi 0

### Bağımsız doğrulayıcı koşumu (Task ID: 8-test)

Geliştirici koşumu birebir teyit edildi: pytest 592/592 (fix öncesi), ruff+
mypy temiz, vitest 31/31, build 14 route, smoke 39/39, secret_scan TEMİZ,
pip-audit + npm audit 0 zafiyet, bağımsız alembic 0006↔0005 roundtrip temiz,
smoke logunda credential izi 0. **18 kritik node-id TEK TEK** koşuldu (hepsi
PASS). Bağımsız probe'lar: P1 `is_active` enjeksiyonu → 422 extra_forbidden
(ENGELLENDİ); P2 username normalize→pattern sırası kanıtlandı
(`"  Admin2 "` → 201 `admin2`; case-bypass yok); P4 12 eşzamanlı DB-fren
isteğinde tam 5 izin / 12 hit — **UPSERT+RETURNING atomikliği canlı kanıt**.

### Bulgu kapatma (bağımsız doğrulayıcı 8-test sonrası)

| Bulgu | Kapatma |
|---|---|
| **F1 orta** — 413/400 yanıtları güvenlik başlıkları + X-Request-ID almıyor (BodySizeLimit middleware'i SecurityHeaders'ın DIŞINDA kalıyor; `add_middleware` insert(0) semantiği) | **Kapatıldı**: main.py ekleme sırası ters çevrildi (dıştan içe: RequestId → SecurityHeaders → BodySizeLimit) + regresyon testi `TestBodySizeLimitResponseHeaders::test_413_response_carries_security_headers_and_request_id` (PASS); smoke 39/39 yeniden koşuldu |
| **F2 düşük** — parola değişiminde new == current engellenmiyor ("rotasyon yapıldı" yanılsaması) | **Kapatıldı**: change_my_password + reset_user_password'de aynı-parola reddi (422 `same_password`); 2 regresyon testi PASS |
| **F3 bilgi** — eşzamanlı çift create UNIQUE yarışı → 500 | **Kapatıldı**: IntegrityError → rollback + idempotent 409 `username_taken` (Faz 07 F3 kalıbı) |
| **F6 bilgi** — backup script kısmi-dump koruması yalnızca boyut eşikli | **Kapatıldı**: backup sonrası `pg_restore -l` archive doğrulaması eklendi (kesik/karışmış dump reddedilir) |
| **F4 bilgi** — audit commit'ten sonra yazılıyor (auditsiz değişiklik penceresi) | Belgelendi: Faz 06 F9 / Faz 07 F8 ile aynı bilinçli kalıp (audit arızası akışı bozmaz; kalıcı iz satır durumunda) |
| **F5 bilgi** — DatabaseRateLimiter dialect cache / cleanup counter instance-bazlı | Belgelendi: pratikte tek engine; çok-prosesli temizlik işlevsel (her proses kendi N=100'ü) |
| **F7 bilgi** — compose NEXT_PUBLIC_API_BASE_URL / RATE_LIMIT_BACKEND=memory yerel değerler | Belgendi: deployment.md §2.1 çok-proses + origin yönlendirmesi operatör kararına dokümante |

Fix sonrası son durum: **pytest 595/595**, ruff temiz, mypy 77 dosya temiz,
smoke **39/39**.

## 3. Mimari kararlar ve varsayımlar

1. **Cookie+CSRF yeniden değerlendirmesi → Bearer modeli KORUNDU.** Kimlik
   cookie ile taşınmadığı için CSRF vektörü yapısal olarak uygulanamaz;
   localStorage+XSS riski `dangerouslySetInnerHTML` yasağı (testle kalıcı),
   15 dk access TTL, CSP `default-src 'none'` (API) ve frontend güvenlik
   başlıklarıyla (proxy katmanı) sınırlanır. Cookie'ye geçiş ayrı bir tasarım
   değişikliği ister; mevcut modelin tehdit modeli bu fazda tekrar
   değerlendirildi ve kabul edildi (phase-05 kararının Faz 08 teyidi).
2. **jti denylist YOK.** Faz 05'te "Faz 08'de" diye not düşülmüştü; karar:
   gerekmez — her istekte DB'den `is_active` okunur; kullanıcıyı devre dışı
   bırakmak TÜM oturumlarını anında düşürür (test kanıtı) ve refresh akışı da
   aynı kapıdan geçer. Ayrıca Faz 08 ile pasif hesap YENİ token da edinemez
   (`authenticate_user` is_active kontrolü — savunma derinliği).
3. **Paylaşımlı fren = DB tabanlı sabit pencere.** Redis eklemek yerine mevcut
   DB kullanıldı (stack sadeliği; AGENTS.md §2). ON CONFLICT UPSERT + RETURNING
   ile atomik; PostgreSQL + SQLite destekli. Fail-closed: DB hatasında fren
   istisna fırlatır (login zaten DB'siz çalışamaz). Sabit pencere, kayan
   pencereye göre tek-UPSERT yarış güvenliği için bilinçli tercih.
4. **Prod observe-only validator.** "Üretime geçişte observe-only varsayılanı"
   katı yorumlandı: prod + `policy_mode=dry_run` başlangıç RED. Escape hatch
   (`REMEDIATION_PROD_ALLOW_DRY_RUN=true`) ayrı anahtar — iki bağımsız kapı
   ilkesiyle (Faz 07 kalıbı).
5. **Kullanıcı silme endpoint'i YOK.** is_active=false tercih edilir (audit izi
   + FK geçmişi korunur). Son-aktif-admin ve self-disable korumaları kilitleme
   vektörünü kapatır; bootstrap parolası yalnızca users BOŞSA işler (tuzak
   kapısı değil).
6. **Admin self-sıfırlama admin ucunda kapalı** (409 use_self_endpoint): parola
   değişimi önbilgi doğrulaması ister; token çalınsa bile parola değişimi
   mevcut parolayı bilmeyene kapalı kalır.
7. **Gövde tavanı Content-Length hızlı yolu + chunked tamponlama**: tavan aşımı
   okunmadan reddedilir; bellek tavanla sınırlı. Reverse proxy katmanı
   (deployment §4) ikinci savunmadır.
8. **Dependency yükseltmeleri** yalnızca bilinen zafiyet gerekçesiyle yapıldı
   (gerekçesiz yükseltme yasağına uyum); her adımda tam test paketi koşuldu.
   npm `overrides` yalnızca transitive postcss fix için kullanıldı.

## 4. Güvenlik etkisi

- Yeni saldırı yüzeyi: /users uçları (admin) + /users/me/password (kimlikli).
  Yüzey, admin dependency + iş kuralı korumaları + audit ile sınırlı; parola
  değeri hiçbir yanıtta/audit'te yok (şema seviyesinde garanti).
- Prod başlangıç yüzeyi daraldı: /docs, /redoc, /openapi.json prod'da kapalı.
- Yanıt başlıkları tüm uçlarda (401/404 dahil) savunmacı; kimlikli yanıtlar
  no-store ile önbelleğe girmez.
- Fren deposu artık çok prosesli dağıtımda tutarlı (paylaşımlı sayacın yok
  sayılmasıyla açılan bypass kapısı kapanmıştır).
- Non-root + cap_drop + read_only + internal network: konteyner kaçış/denetim
  yüzeyi küçültüldü (compose doğrulaması kullanıcı makinesinde).
- Audit whitelist 4 eylemle genişledi; append-only kilidi (test) korunur.

## 5. NOT RUN (sandbox kısıtı) — kullanıcı makinesi komutları

Sandbox'ta Docker/Ollama/gerçek PostgreSQL yoktur; aşağıdakiler koşulmadı:

```bash
# 1) Compose stack + non-root/segmentasyon doğrulaması:
cd ajant && docker compose up -d --build
docker compose exec backend id            # uid=10001(appuser)
docker compose exec db ss -tlnp | grep 5432   # yalnızca iç ağ
ss -tlnp | grep -E ':(8000|3000)' | grep -v 127.0.0.1   # boş çıktı beklenir

# 2) Port taraması (YALNIZCA yetkili staging):
nmap -sT -p- <staging-ip>   # beklenen: 22?, 443 (proxy); 5432/9200/11434 DIŞARIDA KAPALI

# 3) TLS: Caddy kurulumu + sertifika doğrulama (deployment §4) + HSTS başlık kontrolü:
curl -sI https://<panel> | grep -i strict-transport-security

# 4) Backup/restore testi (phases/08 test promptu):
./scripts/backup_db.sh ./backups --prune-days 30
./scripts/restore_db.sh backups/<yeni>.dump
docker compose exec db psql -U ajant -c 'SELECT count(*) FROM events;'

# 5) Disk dolması simülasyonu (gerçek): staging'te küçük bir tmpfs/birimde
#    backend çalıştırıp DISK_CHECK_PATH'i oraya ver; %10 altında low_space beklenir.

# 6) Gerçek PostgreSQL ile migration: 0006 JSONB/davranış farkı yok (sayaç
#    tablosu); alembic upgrade head compose içinde otomatik.

# 7) Brute-force gözlemi gerçek tarayıcıda: AUTH_RATE_LIMIT_PER_MINUTE=3 ile
#    4. hatalı giriş 429 ("Çok fazla deneme").
```

## 6. Bilinen sorunlar / kalan riskler

- Compose/non-root/port taraması doğrulaması kullanıcı makinesine kalır (§5).
- Sabit pencere fren, kayan pencereye göre pencere sınırında 2x patlamaya
  izin verir (tasarım tercihi; atomiklik için kabul edildi — belgelendi).
- Rate limit DB deposu tek DB'ye bağlı; çok düğümlü dağıtım için Redis yol
  haritası (deployment §12).
- audit yazım hatası akışı bozmaz (bilinçli kalıp; "uyarı eşiği bağlama" notu
  bildirim yol haritasına taşındı).
- Frontend token'ları localStorage'dadır (XSS yüzeyi testle kısıtlı; cookie
  geçişi yol haritası kararı §3.1).
- Backend Dockerfile'da baz imaj digest pinleme: prosedür deployment §10'da;
  sandbox'ta registry digest alınamadı (staging'de uygulanmalı).
