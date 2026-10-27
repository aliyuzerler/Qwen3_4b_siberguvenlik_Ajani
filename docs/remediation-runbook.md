# Müdahale Runbook — Kill Switch, Rollback ve Mitigation (Faz 07)

Bu runbook, ajant müdahale alt sisteminin **güvenli kullanımı ve acil
durum müdahaleleri** içindir. Faz 07 kapsamında yürütme daima **dry-run
simülasyonudur**; gerçek sistem değişikliği yapan kod yolu YOKTUR. Bu
dokümandaki rollback adımları (a) simülasyon sonrası durum temizliği ve
(b) gelecekteki gerçek entegrasyonlar için hazırlık amacı taşır.

> Ürün ilkesi (AGENTS.md §4): Model eylem başlatamaz. Öneri → deterministik
> politika motoru → insan onayı → yürütme zinciri olmadan hiçbir aksiyon
> çalışmaz. Serbest shell komutu yoktur; yalnızca allowlist'teki tipli
> aksiyonlar önerilebilir.

---

## §1 — Kill switch: acil durdurma

**Ne yapar:** `REMEDIATION_ENABLED=false` → yeni öneri OLUŞTURULAMAZ ve
yürütme REDDEDİLİR (HTTP 503 `kill_switch`). Katalog okuma uçları ve mevcut
öneri kayıtları panel/API'de okunmaya devam eder (iz kaybı yok).

**Ne zaman kullanılır:**
- Politika motorunda bir açıklık şüphesi,
- Yanlış yapılandırılmış allowlist/parametre davranışı,
- Yürütme katmanında beklenmeyen davranış (executor hataları artışı),
- Herhangi bir güvenlik olayı şüphesi.

**Adımlar (uygulama süresi: bir yeniden başlatma):**

```bash
# 1) backend/.env dosyasında:
REMEDIATION_ENABLED=false

# 2) backend'i yeniden başlat (compose örneği):
docker compose restart backend

# 3) Doğrula: /ready etkilenmez; öneri ucu 503 dönmeli:
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8000/api/v1/remediation/actions \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"action_type":"notify_admin","event_ids":["..."],"justification":"kill switch kontrolu","idempotency_key":"ks-check-1"}'
# beklenen: 503 (code=kill_switch)
```

**Mod anahtarı ile farkı:** `POLICY_MODE=observe_only` (varsayılan) yalnızca
YÜRÜTMENİ engeller; öneri hazırlığı devam edebilir. Kill switch tüm alt
sistemi kapatır. Acil durumda önce kill switch; kalıcı çözümde ikisi birlikte.

---

## §2 — Aksiyon bazlı rollback/mitigation

Her öneri satırı kendi `rollback_note` alanını taşır (öneri anındaki
katalog metni snapshot'lanır). Katalogdaki tanımlar:

### 2.1 `notify_admin` (düşük risk)
- Etki: panel/bildirim kaydı; sistem değişikliği yok.
- Rollback: gerekmez. Kayıt append-only'dir; panelde arşivlenir.

### 2.2 `restart_wazuh_agent` (orta risk)
- Etki: hedefte kısa süreli telemetri kesintisi.
- Rollback (gerçek entegrasyonda):
  1. `systemctl status wazuh-agent` ile servis durumunu doğrula.
  2. Ajan başlamadıysa `journalctl -u wazuh-agent -n 50` ile hata incele.
  3. Gerekirse `systemctl restart wazuh-agent` (idempotent) tekrarla.
  4. Indexer'da agent heartbeat'inin döndüğünü doğrula
     (`wazuh-alerts-*` son 10 dk içinde agent kaydı).

### 2.3 `run_antivirus_scan` (orta risk)
- Etki: hedefte CPU/IO yükü artışı; sistem değişikliği yapmaz.
- Rollback: hedefteki AV/EDR konsolundan taramayı durdur; sonuç raporunu arşivle.

### 2.4 `block_src_ip` (YÜKSEK risk — VARSAYILAN ENGELLİ)
- Etki: firewall kuralı; yanlış hedef meşru erişimi/panel-Wazuh iletişimini
  KESER.
- Rollback (gerçek entegrasyonda):
  1. Yürütme kaydındaki kural ID'sini bul (execution_result).
  2. Kuralı kaldır: `firewall-cmd --remove-rich-rule='...'` veya eşdeğeri.
  3. Bağlantıyı doğrula: hedef IP'den panel/Wazuh'a erişim testi.
- Ön şart (iki bağımsız kapı):
  `REMEDIATION_ALLOW_BLOCKED_ACTIONS=true` **ve** admin PATCH enable. Üretimde
  (`APP_ENV=prod`) global kapı AÇILAMAZ — uygulama başlamayı reddeder.

### 2.5 `isolate_host` (YÜKSEK risk — VARSAYILAN ENGELLİ)
- Etki: hedef sunucunun ağ erişimi kesilir (üretim servisleri etkilenebilir).
- Rollback: NAC/firewall izolasyon kuralını kaldır; erişimi doğrula; olay
  kaydına kural ID'sini işle.

### 2.6 `lock_user_account` (YÜKSEK risk — VARSAYILAN ENGELLİ)
- Etki: SSH/oturum erişimi kesilir; kilitli servis hesabı kesinti üretir.
- Rollback: `passwd -u <user>` (yerel) veya dizin servisi ters adımı;
  oturum testi yap.

---

## §3 — Tekrar/replay ve durum makinesi kurtarma

- **Yürütme tekrarı (replay):** Aynı `execution_key` ile gelen istek orijinal
  sonucu `replayed=true` ile döner; çift yürütme OLMAZ. Farklı anahtarla
  tekrar → 409 `already_executed`.
- **Öneri tekrarı:** Aynı `idempotency_key` → aynı satır döner (yeni satır
  yazılmaz).
- **Onay süresi dolarsa:** Satır `expired` olur; yeni öneri oluşturulmalıdır
  (`REMEDIATION_APPROVAL_TTL_MINUTES`, varsayılan 60 dk).
- **`failed` durumundaki öneri:** Yürütme sonucu `execution_error` içinde
  incelenir; kök neden çözülmeden tekrar denenmez (farklı execution_key ile
  yürütme 409 ile reddedilir — satır başına tek yürütme).

## §4 — Görev ayrımı istisnası (tek-admin kurulum)

Varsayılan: öneren kendi önerisini onaylayamaz (409 `self_approval`). Tek
admin'li küçük kurulumlarda bilinçli tercih ile açılabilir:

```bash
# backend/.env:
REMEDIATION_ALLOW_SELF_APPROVAL=true
# yeniden başlat; bu durumda audit kayıtları öneren=onaylayan gösterir.
```

> Öneri: üretimde İKİ admin hesabı ile görev ayrımı korunmalıdır. İkinci
> kullanıcıyı bootstrap sonrası eklemek için Faz 08 kullanıcı yönetimi
> beklenir; şu an tek yol DB seviyesinde argon2id hash ile INSERT'tir
> (docs/phase-07-verification.md §5 komut listesi).

## §5 — İzleme ve kanıt

- Tüm geçişler `audit_log`'a yazılır: `remediation.action.{proposed, approved,
  rejected, executed, failed, blocked, replayed, rate_limited}` ve
  `remediation.catalog.updated`.
- Panel: `/remediation` (liste+katalog), `/remediation/[id]` (kanıt paketi +
  politika kararı + yürütme sonucu). Admin: `/audit`, `/settings`.
- Politika redleri `detail.checks` ile satırda saklanır: "neden reddedildi"
  sorusu öneri detayından cevaplanır.

## §6 — Bilinen sınırlar (Faz 07)

- Yürütme daima DryRunExecutor: `simulated=true`. Gerçek Wazuh/EDR/firewall
  entegrasyonu BU fazda yazılmadı (yazılması ayrı güvenlik incelemesi gerektirir).
- Yürütme yolu satır kilidi (SELECT ... FOR UPDATE) ile korunur (PostgreSQL);
  GERÇEK yürütücü eklenmeden önce: kilidin gerçek PG'de doğrulanması + executor
  tarafında idempotency (kural ID kaydı) zorunludur (bağımsız doğrulama bulgusu F2).
- Rate limit bellek içi tek proses (Faz 08'de paylaşımlı depo).
- `policy_mode` enum'unda "gerçek yürütme" modu YOKTUR: `observe_only |
  dry_run`. Eklenmesi, bu runbook'un güncellenmesini ve ayrı bir tehdit
  modeli incelemesini gerektirir.
