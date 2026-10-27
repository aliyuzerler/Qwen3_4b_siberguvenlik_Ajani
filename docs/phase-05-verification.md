# Faz 05 Doğrulama Raporu — Güvenlik Paneli (Auth/RBAC + Olaylar + AI Değerlendirmesi)

Durum: **PASS** (mock-first sandbox kapsamı; saha adımları aşağıda)
Kod: Faz 05 commit'i (aşağıda tek commit); bağımsız doğrulayıcı kaydı: worklog Task ID 5-test

## 1. Kabul matrisi (satır 05) — gereksinim → kanıt

| Gereksinim | Kanıt |
|---|---|
| **Auth/RBAC** | argon2id parola karması (`app/services/security/passwords.py`; öneki + tuz benzersizliği testli); JWT HS256, decode'da algoritma AÇIKÇA verilmiş (alg confusion testli), access/refresh typ ayrımı (çapraz kullanım 4 testle RED); yetki kararı token rolünden DEĞİL, DB'den güncel `is_active`+rol (`load_active_user`); `require_role` router TANIM anında bağlanır (audit/settings — atlama hatası yapılamaz); bootstrap admin (`main.py` lifespan; parola log'a yazılmaz); 3 rol viewer/analyst/admin 7 testli matris. Testler: `test_rbac_api.py`, `test_auth_api.py`, `test_auth_flow.py` |
| **Olay listesi/detayı** | `GET /api/v1/events` (sayfalı), `GET /api/v1/events/{id}` (orijinal kanıt + AI kaydı AYRI nesneler); unknown id 404, malformed id 422; boş liste `{items: [], total: 0}`. Testler: `test_events_api.py` |
| **Filtreler** | assessment (completed/analysis_failed/none), rule_level_min (0-15 doğrulamalı), source, agent_name, q (parameterized LIKE + `%`/`_`/`\` kaçışı — literal arama testli), since/until (ISO). Parametre sınırları 422 ile korunur. |
| **AI değerlendirmesi (görsel ayrım)** | Backend: `rule_level` (ORİJİNAL Wazuh) ile `analysis.ai_assessment` AYRI alanlar — model asla severity üzerine yazmaz (AGENTS.md §5). Frontend: orijinal kanıt gri kartta, model çıktısı **mor çerçeveli ayrı kartta** + "AI çıktısı — doğrulanmalı" rozeti; `analysis_failed` durumunda "güvenilir değerlendirme YOKTUR — orijinal veriyi esas alın" uyarısı. Testler: backend `TestEventDetail` + frontend `ui.test.tsx` |
| **Hata/boş/loading durumları** | `states.tsx`: LoadingState (`role=status`, `aria-live`), EmptyState, ErrorState (`role=alert` + yeniden dene), ForbiddenState (403 ayrı kart); 6 sayfanın tamamında kullanım; sayfa geçişlerinde `keepPreviousData`. Testler: `ui.test.tsx` + backend `TestEmptyState` |

## 2. phases/05 test promptu — madde madde

| Madde | Durum |
|---|---|
| Oturum açma/kapama | PASS (login testleri + logout `clearTokens` + query reset; 401'de otomatik çıkış) |
| Rol izinleri | PASS (7 testlik matris: viewer/analyst/admin × korunan uçlar) |
| Yetkisiz API çağrıları | PASS (tokensız 401 + WWW-Authenticate; sahte token 401) |
| Yetkisiz kullanıcı alert'e doğrudan ID ile erişememe | PASS (pasif kullanıcının geçerli token'ıyla liste VE `GET /events/{uuid}` → 401) |
| Listeleme/filtreleme/sayfalama | PASS (11 test; sayfa sınırı 422; joker karakter kaçışı) |
| Olay detayı | PASS (orijinal + AI ayrımı; analysis yoksa null) |
| Boş/hata/loading | PASS (iki katmanda da testli) |
| XSS payload (log + AI çıktısı) | PASS (backend: payload kayıpsız JSON string, yanıt HTML değil; frontend: script/img ELEMENT olarak DOM'a girmez; `dangerouslySetInnerHTML=` prop kullanımı vitest kaynak taramasıyla kalıcı olarak yasak) |
| CSRF (uygulanabilirse) | **N/A — gerekçe:** kimlik Bearer başlığıyla taşınır; cookie oturumu YOK (tarayıcı kimlik bilgisini otomatik eklemez → cross-site istek oturum taşımaz). Karar `src/lib/api.ts` ve `app/api/v1/auth.py` içinde belgeli; CORS `allow_credentials=False` (Faz 05). Cookie+CSRF-token modeli Faz 08'de yeniden değerlendirilecektir. |
| Rate limit | PASS (giriş/refresh IP başına 10/dk; 429 + Retry-After; diğer uçlar etkilenmez; bellek içi tek-proses sınırlaması belgeli — Faz 08'de paylaşımlı depo) |
| Secret sızması (network/log) | PASS (backend şemasında secret ALANI yok; yanıt + uvicorn log taraması temiz; audit detail yalnızca yapısal küçük sözlük) |
| Görsel inceleme | NOT RUN (aşağıda) — işlevsel testler 16/16 |

## 3. Test/bağımsız doğrulama dengesi

- Backend: **366 passed** (Faz 04 sonu 281 → +85), 0 failed; ruff temiz; mypy 58 dosya temiz
- Alembic roundtrip BAĞIMSIZ: upgrade head → `0003_auth`; downgrade 0002 → tekrar head ✓ (users + audit_log sütun/CHECK/UNIQUE assertleri explicit)
- Frontend: **vitest 16/16**; `npm run build` başarılı (9 route)
- Canlı smoke (uvicorn + sqlite + mock Wazuh): **16/16 PASS** — /ready bileşenleri, 401/403, yanlış parola tek biçimli mesaj, token akışı, korunan 6 uç, AI ayrımı, audit izleri, 429 freni, secret taraması, build çıktısı
- Bağımsız doğrulayıcı (Task 5-test): 26 negatif senaryo TEK TEK koşuldu — hepsi PASS; kabul satırı 05: **5/5 PASS** önerildi

## 4. Doğrulayıcı bulguları ve kapatma durumu

| ID | Önem | Bulgu | Durum |
|---|---|---|---|
| B1 | Orta | `docs/phase-05-verification.md` eksik (dangling referans) | **KAPATILDI** — bu doküman yazıldı |
| B2 | Orta | compose'da migration adımı yok; boş pgdata'da ilk kurulum çökerdi | **KAPATILDI** — `docker-compose.yml` backend `command: alembic upgrade head && uvicorn …` |
| B3 | Düşük | deps.py docstring'te yanlış test adı | **KAPATILDI** — gerçek test adına işaret ediyor |
| B4 | Düşük | 6× deprecated `HTTP_422_UNPROCESSABLE_ENTITY` | **KAPATILDI** → `HTTP_422_UNPROCESSABLE_CONTENT` |
| B5 | Düşük | login testinde act() uyarısı | **KAPATILDI** — resolve act içinde; uyarı gitti |
| B6 | Bilgi | token localStorage'da (XSS'te okunabilir yüzey) | **Bilinçli karar** — api.ts'te belgeli; kısa access TTL; Faz 08'de cookie+CSRF yeniden değerlendirme |
| B7 | Bilgi | CORS `allow_credentials=True` gereksiz | **KAPATILDI** → `False` (Bearer modeli) |
| B8 | Proses | Faz 05 değişiklikleri commit edilmemiş | **KAPATILDI** — bu dokümanla birlikte tek commit |

## 5. NOT RUN (sandbox kısıtı) — kullanıcı makinesi adımları

Sandbox'ta Docker, PostgreSQL ve gerçek Ollama YOKTUR. Aşağıdakiler saha adımıdır:

```bash
# 0) Yapılandırma
cp backend/.env.example backend/.env
#   → JWT_SECRET (32+ karakter) ve ADMIN_BOOTSTRAP_PASSWORD gerçek değerlerle doldurun

# 1) Tam stack (migration artık konteyner başlangıcında otomatik — B2)
docker compose up --build -d
curl -s http://localhost:8000/api/v1/ready   # database/wazuh/ollama durumları

# 2) Ollama + model
ollama pull qwen3:4b && ollama list

# 3) Uçtan uca akış (.env): WAZUH_SOURCE_MODE=mock + WORKER_LOOP_ENABLED=true → restart backend
#    Panelde olaylar analizle akar; boş kalan analysis_failed yolunu görmek için
#    Ollama'yı durdurup döngüyü izleyin (satır yazılmaz — doğrulama noktası)

# 4) Tarayıcı smoke: http://localhost:3000
#    - ADMIN_BOOTSTRAP_PASSWORD ile giriş; olay listesi → detay; AI mor kartı ayrımı
#    - 10 yanlış parola → 429 + Retry-After
#    - DevTools Network: yalnızca Authorization: Bearer; cookie credential AKIŞI YOK (CSRF N/A kanıtı)

# 5) Gerçek PostgreSQL roundtrip (opsiyonel)
docker compose exec backend alembic current
docker compose exec backend alembic downgrade 0002_analyses
docker compose exec backend alembic upgrade head
```

## 6. Mimari kararlar (bu fazda alınanlar)

1. **Yetki kararı sunucuda, DB'den**: token'daki rol yalnızca ipucu; her istekte güncel `is_active`/rol okunur — pasif kullanıcı token'ı anında değersizleşir.
2. **Audit append-only**: `audit_log`'a yalnızca INSERT; UPDATE/DELETE kod yolu yok ve kaynak-taramalı testle kalıcı kilit altında. actor FK YOK (kullanıcı silinse iz kalır). Action whitelist sabitleri.
3. **Bearer taşıma → CSRF N/A**: cookie oturumu yok; CORS `allow_credentials=False`. Faz 08'de cookie+CSRF-token alternatifi değerlendirilecek.
4. **Rate limit bellek içi** (tek proses): compose dağıtımı tek backend prosesi; Faz 08'de paylaşımlı depo. Kapsam: /auth/login + /auth/refresh.
5. **Mock AI YOK**: model erişilemezse analiz yazılmaz; panelde "analiz yok/başarısız" dürüst gösterilir (Faz 04 kararı korunur).
6. **Ayar güncelleme ucu yok**: .env + restart tek değişim yolu (değişmez yapılandırma; Faz 08 değerlendirir). Settings yanıtı şema düzeyinde secretsız.
7. **Frontend görsel ayrım**: AI çıktısı mor aile + "doğrulanmalı" rozeti; Wazuh orijinali gri aile. `dangerouslySetInnerHTML` yasak ve testle kilitli.

## 6.1 Faz 05'i Faz 06+ için etkileyen notlar

- `analyses` UNIQUE(event_id): yeniden analiz (model yükseltmesi) gelecek fazda ayrı migration ile açılacak (Faz 04 kararının devamı).
- `requires_human_review` sqlite'ta 0/1 integer; API katmanında bool'a çevrilir (panel doğru gösterir).
- Panel API'si salt okunurdur; Faz 06 korelasyon + Faz 07 dry-run uçları mevcut RBAC iskeletinin üzerine `require_role(ROLE_ANALYST)`/`ROLE_ADMIN` ile eklenebilir.
- Çıkışta sunucu tarafı revocation yok (stateless JWT); Faz 08'de jti denylist planlı.
