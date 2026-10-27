# Faz 07 Doğrulama — Güvenli Müdahale Hazırlığı

Kapsam: `phases/07-remediation-guardrails.md` + kabul satırı 07
("Başlangıçta dry-run; allowlist; insan onayı; audit; timeout; rollback/kill
switch") + `phases/TEST-PROMPT-TEMPLATE.md`.

Tüm test verisi SENTETİKTİR (RFC 5737 doküman IP'leri, örnek kullanıcı adları).
Bu doküman geliştirici koşumunu raporlar; bağımsız doğrulayıcı koşumu
(worklog `Task ID: 7-test`) ayrıdır.

---

## 1. Gereksinim → Kanıt matrisi

| Gereksinim (phases/07) | Uygulama | Kanıt |
|---|---|---|
| Başlangıç modu observe_only/dry_run | `POLICY_MODE` enum **yalnızca** `observe_only\|dry_run` (config; "gerçek yürütme" modu kodda YOK); varsayılan `observe_only` | `test_remediation_security.py::test_observe_only_is_default_policy_mode`; smoke 22/22 (Evre A observe_only yürütme 409) |
| Tipli action enum; serbest shell komutu yok | 6 aksiyon kataloğu (`catalog.py`); param şemaları `extra="forbid"`; `command/args/shell` alanları ValidationError | `test_remediation_catalog.py` (13 test); `test_free_form_command_field_is_rejected`; smoke firewall 422 |
| Allowlist | Aksiyon **yalnızca katalogda tanımlıysa** önerilebilir; DB'de `remediation_catalog.enabled` operatör anahtarı; admin PATCH (audit'li) | `test_remediation_policy.py::test_unknown_action_type_rejected`; `TestCatalogEndpoint` |
| Hedef kapsamı + argüman doğrulama | `SCOPE_AGENT_ID`/`SCOPE_SRC_IP`/`SCOPE_ANY_EVENT`: hedef değeri kanıt paketiyle eşleşmezse RED; tipli param tavanları | `TestTargetScope` (4 test); `test_wrong_target_rejected` (API) |
| TTL | `REMEDIATION_APPROVAL_TTL_MINUTES` (60 dk): onay→yürütme penceresi; aşım → `expired` + 409 | `test_expired_approval_blocks_execution`; smoke 2 evre |
| Rate limit | Kullanıcı başına saatlik tavan (create+execute; 429 + Retry-After + audit) | `test_rate_limit_blocks_creation`; `test_execute_rate_limit` |
| İnsan onayı + onaylayan kaydı | `approve` (admin) → `approved_by_user_id/username/at`; görev ayrımı: öneren≠onaylayan (escape hatch: `REMEDIATION_ALLOW_SELF_APPROVAL`, vars. false) | `test_self_approval_denied`; `test_second_admin_can_approve_and_recorded`; smoke self-approval 409 |
| Eylem öncesi kanıt paketi | Sunucu üretimi (`build_evidence`): event/alert/rule/agent/src_ip/max_rule_level/pencere + risk açıklaması + rollback notu snapshot | `test_create_builds_server_side_evidence`; smoke kanıt kontrolü |
| Kill switch | `REMEDIATION_ENABLED=false` → öneri+yürütme 503 `kill_switch`; katalog okuması açık | `test_kill_switch_blocks_creation`; runbook §1 |
| Rollback/mitigation runbook | `docs/remediation-runbook.md`: per-aksiyon rollback + kill switch prosedürü + replay kurtarma | doküman + `rollback_note` snapshot'ı öneri satırında |
| Firewall/SSH işlemleri varsayılan engelli | `block_src_ip`/`isolate_host`/`lock_user_account` → `default_blocked=True`; **iki bağımsız kapı** (global env prod'da YASAK + admin enable); DB default `enabled=false` | `TestDefaultBlockedGate`; `test_firewall_action_still_blocked_when_admin_enables_only`; `test_prod_cannot_enable_blocked_actions` |
| Her sonucun/hatanın audit'i | 9 yeni AuditAction; redler dahil TÜM geçişler audit_log'a (tek nokta: servis katmanı) | `test_unknown_action_type_rejected_and_audited`; smoke audit kontrolleri |
| Model eylem başlatamaz | analysis/worker/normalization paketlerinde remediation import'u YASAK (AST tarama); öneri yalnızca kimlikli insan ucundan (`requested_by_*` zorunlu) | `TestModelIsolation` (2 test) |
| Timeout | `execute_with_timeout` (vars. 10 sn) → `failed` + `executor_timeout` | `test_executor_timeout_marks_failed` |
| İlk testlerde fake executor | Pakette **gerçek yürütücü yok**: AST tarama subprocess/socket/system/popen yasağı; tek somut sınıf `DryRunExecutor` (simulated=true daima); testler `FakeRemediationExecutor` (conftest) kullanır | `TestNoRealExecutor` (4 test); `test_observe_only_blocks_execution_and_never_calls_executor` (fake.calls==0 kanıtı) |

## 2. Test promptu kapsamı → sonuç (geliştirici koşumu)

Test promptundaki senaryoların TÜMÜ koşuldu (pytest `tests/test_remediation_*.py`):

| Senaryo | Sonuç | Test |
|---|---|---|
| modelden gelen serbest komut | PASS (422 `invalid_params`; command/args/shell reddedilir) | catalog+policy+API üç düzey |
| bilinmeyen action type | PASS (422 `unknown_action_type` + audit blocked) | policy + API |
| yanlış hedef | PASS (422 `target_scope`) | policy + API |
| eksik onay | PASS (409 `not_approved`; executor çağrılmaz) | API |
| süresi dolmuş onay | PASS (409 `approval_expired`; status=expired + audit) | API |
| tekrar oynatılan istek | PASS (aynı key→`replayed=true` çift yürütme yok; farklı key→409) | API |
| rate limit | PASS (429 + Retry-After + audit) | API |
| kill switch | PASS (503 `kill_switch`) | API |
| audit DB hatası | PASS (audit_log DROP → akış tamamlanır, durum satırı yaşar, hata loglanır) | API |
| executor timeout | PASS (failed + executor_timeout) | API |
| gerçek executor çağrısı YOK | PASS (AST tarama + fake.calls sayaçları) | security |
| observe-only'de sistem değişikliği YOK | PASS (409 + executor.calls==0) | API |
| kritik erişimi kesebilecek eylemler RED | PASS (firewall/SSH/hesap default_blocked; iki kapı) | policy + API |

**Toplam koşum (geliştirici):**
- Backend: `pytest tests/ -q` → **533 passed, 0 failed** (121 sn) — Faz 06'dan 457 → +76
  - remediation testleri: catalog 11, policy 17, api 35, security 9 (=72) + migrations +4
- `ruff check app tests` → All checks passed
- `mypy app` → Success: no issues found in 74 source files
- Frontend: `npx vitest run` → **23 passed (5 dosya)**; `npm run build` → başarılı (13 route, +2)
- Canlı smoke: `scripts/phase07_smoke.sh` → **22/22 PASS** (iki evre:
  observe_only yürütme engeli + dry_run simülasyon; replay; görev ayrımı;
  firewall iki kapı; audit; credential taraması temiz)
- Alembic: 0001↔0005 upgrade/downgrade/roundtrip (test_migrations.py)

### Bulgu kapatma (bağımsız doğrulayıcı Task 7-test sonrası)

| Bulgu | Kapatma |
|---|---|
| F1 düşük — smoke check #15 tautolojik | Kapatıldı: smoke script gerçek HTTP kodunu parse eder (`-w '\n%{http_code}'`) |
| F2 düşük(latent) — execute satır kilidi yok (TOCTOU) | Kapatıldı: `_get_action_or_404(lock=True)` → SELECT FOR UPDATE (execute yolu; PG'de kilit, SQLite no-op) |
| F3 bilgi — eşzamanlı aynı idempotency_key → 500 | Kapatıldı: IntegrityError yakalanır → idempotent yola düş (mevcut satır döner) |
| F7 bilgi — kill switch rate-limit sayacından sonra | Kapatıldı: kill switch kontrolü iki uçta limiter'dan ÖNCE |
| F4 bilgi — doküman test sayıları | Kapatıldı: bu bölüm gerçek sayılarla güncellendi (11/17/35/9) |
| F8 bilgi — katalog PATCH commit-sonrası audit penceresi | Belgelendi: Faz 06 F9 ile aynı bilinçli kalıp (audit hatası akışı bozmaz) |
| F5/F6 bilgi — worklog kaydı + commit | Bu kayıt + commit ile kapanır |

## 3. Mimari kararlar ve varsayımlar

1. **Gerçek yürütücü kodda YOK.** Faz 07 "hazırlık" fazıdır: tek somut
   yürütücü `DryRunExecutor`. Gerçek entegrasyon yazılırsa ayrı güvenlik
   incelemesi + tehdit modeli güncellemesi zorunludur (runbook §6).
2. **Mod enum dar:** `observe_only | dry_run`. "Active" modu bilinçli olarak
   mevcut değil (tip seviyesinde garanti; test `test_observe_only_is_default_policy_mode`).
3. **İki bağımsız kapı ilkesi:** firewall/SSH/hesap aksiyonları için global
   env kapısı (prod'da validator ile yasak) + admin enable (audit'li). Tek
   kapı yeterli DEĞİL (savunma derinliği).
4. **Görev ayrımı:** öneren ≠ onaylayan (varsayılan). Tek-admin kurulum için
   bilinçli escape hatch (`REMEDIATION_ALLOW_SELF_APPROVAL`, vars. false,
   runbook §4). Yürütme ayrı bir göz gerektirmez (onay ikinci gözdür).
5. **Kanıt paketi sunucu üretimi:** istemci yalnızca event UUID'leri gönderir;
   alert/rule/agent/IP alanları DB'den kurulur (iz bütünlüğü; istemci kanıtı
   sahteleştiremez).
6. **Audit tek nokta:** redler dâhil tüm geçişler servis katmanından yazılır
   (API katmanı tekrar yazmaz → çift kayıt yok). Audit DB arızasında akış
   BOZULMAZ (AuditService sözleşmesi; kalıcı iz = remediation_actions satır
   durumu). Bu senaryoda rollback ORM nesnelerini expire ettiği için yanıt
   `session.get` ile taze okunur (MissingGreenlet koruması).
7. **Replay koruması:** öneri için `idempotency_key` UNIQUE, yürütme için
   `execution_key` UNIQUE. Aynı anahtar = orijinal sonuç (`replayed=true`);
   farklı anahtar = 409. Satır başına tek yürütme ilkesi.
8. **Katalog hibrit** (correlation_rules kalıbı): tanım kodda, operatör
   `enabled` DB'de; satır silinmez (append-baskın).
9. **Rate limit bellek içi tek proses** (Faz 05 auth freniyle aynı sınırlama;
   Faz 08'de paylaşımlı depo).

## 4. Güvenlik etkisi

- Ek saldırı yüzeyi yok: yürütme daima simülasyon; sistem değişikliği yapan
  kod yolu (subprocess/socket/eval) AST testiyle kalıcı olarak yasak.
- Model→eylem yalıtımı testle kilitli; LLM çıktısına dayalı öneri yolu yok.
- Audit yüzeyi genişletildi: redler dahil 9 yeni eylem adı; whitelist testi
  mevcut (append-only kilidi).
- `.env.example` yalnızca örnek değerler; smoke parolaları sahte ve script
  içinde işaretli (`SAHTE`).

## 5. NOT RUN (sandbox kısıtı) — kullanıcı makinesi komutları

Sandbox'ta Docker/Ollama/gerçek PostgreSQL yoktur; aşağıdakiler koşulmadı:

```bash
# 1) Gerçek PostgreSQL ile migration + compose stack:
cd ajant
docker compose up --build
docker compose exec backend alembic upgrade head   # (compose zaten yapar; doğrulama için)
psql -U ajant -c "\d remediation_actions"           # CHECK/FK/UNIQUE davranışı (0005 JSONB)

# 2) dry_run modunda gerçek panel akışı (tarayıcı):
#    backend/.env: POLICY_MODE=dry_run, REMEDIATION_ALLOW_SELF_APPROVAL=true (tek admin ise)
#    ya da ikinci admin hesabı ekleyin (görev ayrımı korunur):
docker compose exec backend python - <<'PY'
import asyncio, os
async def main():
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    import app.models
    from app.models.user import User
    from app.services.security.passwords import hash_password
    engine = create_async_engine(os.environ["DATABASE_URL"])
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s, s.begin():
        s.add(User(username="admin2", password_hash=hash_password("GUCLU-BIR-PAROLA-degistir"),
                   role="admin", is_active=True))
    await engine.dispose()
asyncio.run(main())
PY
#    Panel: /remediation → öneri → (admin2 ile) onay → yürüt → "SİMÜLASYON" rozeti

# 3) Kill switch tatbikatı:
#    backend/.env: REMEDIATION_ENABLED=false → docker compose restart backend
#    → panelde öneri oluşturma 503; katalog/liste okunur (runbook §1)

# 4) Rate limit gözlemi: REMEDIATION_RATE_LIMIT_PER_HOUR=3 ile 4. öneri 429
```

## 6. Bilinen sorunlar / kalan riskler

- Yürütme gerçek değildir (tasarım gereği); gerçek entegrasyon Faz 08+ ayrı
  inceleme konusudur.
- Rate limit tek proses; çok replikalı dağıtımda paylaşımlı depo gerekir (Faz 08).
- Kullanıcı yönetimi ucu yoktur: görev ayrımı için ikinci admin eklemek
  şu an DB seviyesinde yapılır (verification §5.2 komutu).
- `remediation_catalog` senkronu yalnızca ekleme yapar; koddan çıkan aksiyon
  satırı DB'de kalır (allowlist kod tarafında zorunlu olduğundan önerilemez;
  eski satırlar iz bütünlüğü için korunur).
- Panelde katalog enable/disable düğmesi yoktur (PATCH API mevcut; UI toggle
  Faz 08 değerlendirme konusu) — correlation rules panelindeki toggle kalıbı
  burada bilinçli olarak uygulanmadı (kritik aksiyonlarda yanlış tıklama riski).
