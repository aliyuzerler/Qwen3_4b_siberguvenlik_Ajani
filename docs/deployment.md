# ajant — Dağıtım ve Operasyon Rehberi (Faz 08)

Kapsam: `phases/08-hardening-and-release.md` gereksinimleri — secret yönetimi,
TLS, güvenlik duvarı, minimum servis yetkileri, dependency pinning,
backup/restore, retention, izleme, log rotation ve incident runbook bağlantısı.

Tüm örnek değerler SAHTE/yer tutucudur (örnek olarak işaretlidir); gerçek
credential repoya asla girmez (AGENTS.md §3).

---

## 1. Mimari ve ağ segmentasyonu

```
                    ┌────────────────────── host makine ──────────────────────┐
tarayıcı ──TLS──► Caddy/nginx :443                                    │
                    │   └─► frontend (127.0.0.1:3000)  [frontend_net] │
                    │   └─► backend  (127.0.0.1:8000)  [frontend_net] │
                    │                    backend  ──► db:5432         │
                    │                    (backend_net — INTERNAL,     │
                    │                     dışarı çıkış YOK)           │
                    │                    backend ──► host:11434       │
                    │                    (Ollama; host.docker.internal)│
                    └─────────────────────────────────────────────────┘
```

- **frontend_net**: tarayıcı erişimi (frontend + backend).
- **backend_net** (`internal: true`): backend ↔ db; internete çıkışı yoktur.
- **DB portu host'a açılmaz** (yalnızca `expose` — compose bunu garanti eder).
- **Backend 8000 ve frontend 3000 yalnızca `127.0.0.1`'e** bağlanır; internete
  açık değildir. Dışarıya yalnızca TLS reverse proxy çıkar.
- **Ollama compose içinde KOŞMAZ** (kullanıcı makinesinde). Backend config
  validator'ı genel FQDN/IP'yi reddeder (`OLLAMA_ALLOW_PUBLIC_HOST=false`
  varsayılan) — "Ollama endpoint'i internete açık bırakılmama" gereksinimi
  iki katmanda zorlanır: config + ağ erişimi. Ollama dış dünyaya KAPALI
  bağlanmalıdır: backend konteynerdeyse `host.docker.internal` trafiği host'a
  docker bridge gateway'inden geldiğinden `OLLAMA_HOST=<docker0-IP>`
  (örn. 172.17.0.1); konteynersız geliştirmede `127.0.0.1`
  (ayrıntı: docs/phase-10-operations.md §3).
- **Wazuh Indexer erişimi**: backend konteynerinden tek yönlü, salt okunur.
  Indexer (9200) yalnızca backend'in bulunduğu ağdan erişilebilir olmalı;
  host güvenlik duvarında Wazuh API/Indexer'ın gerekli ağlarla sınırlandırıldığı
  doğrulanmalıdır (aşağıda §4).

## 2. Kurulum (staging)

Ön koşul: Docker + Docker Compose v2, 32 GB RAM (model CPU modunda), Ollama.

```bash
git clone <repo-url> ajant && cd ajant

# 1) Backend env: örnek dosyayı kopyala, ZORUNLU alanları gerçek değerle doldur
cp backend/.env.example backend/.env
$EDITOR backend/.env      # JWT_SECRET (≥32 karakter), DATABASE_URL parolası,
                          # ADMIN_BOOTSTRAP_PASSWORD (≥12 karakter)

# 2) Compose parolasını da değiştir (SAHTE_YEREL_PAROLA_DEGISTIR yerine)
$EDITOR docker-compose.yml

# 3) Model kurulumu (kullanıcı makinesinde, bir kez)
ollama pull qwen3:4b

# 4) Stack'i başlat (backend: migration'ları otomatik uygular)
docker compose up -d --build

# 5) Doğrula
curl -s http://127.0.0.1:8000/api/v1/health     # {"status":"ok"}
curl -s http://127.0.0.1:8000/api/v1/ready      # components: db/wazuh/ollama/disk
```

İlk girişte `ADMIN_BOOTSTRAP_PASSWORD` ile `admin` hesabı oluşur (users tablosu
boşsa; parola değeri log/yanıta yansıtılmaz). Panel: `http://127.0.0.1:3000`.

### 2.1 Çok prosesli backend (opsiyonel)

Tek proses varsayılandır. Birden fazla uvicorn worker çalıştırılacaksa
frenlerin prosesler arası paylaşımlı olması ZORUNLUDUR:

```env
RATE_LIMIT_BACKEND=database   # rate_limit_counters tablosu (alembic head)
```

## 3. Secret yönetimi

- Tüm sırlar `backend/.env` üzerinden verilir; dosya **git'te DEĞİLDİR**
  (`.gitignore`); izinleri `chmod 600 backend/.env` yapılmalıdır.
- `JWT_SECRET` ≥ 32 rastgele karakter: `openssl rand -hex 32`.
- Rotasyon: `JWT_SECRET` değişince tüm JWT'ler geçersizleşir (imza doğrulaması
  düşer) → kullanıcılar yeniden giriş yapar; panel için kabul edilebilir kesinti.
  Değişiklik sonrası `docker compose up -d backend` (yeniden başlatma).
- Yedek dosyaları (`backups/*.dump`) VERİ İÇERİR: `chmod 600` + şifreli birim.
- Üretimde Docker secret / systemd `EnvironmentFile` / hashicorp vault geçişi
  yol haritasındadır (§Yol haritası).

## 4. TLS ve güvenlik duvarı

Uygulama düğümünde TLS'i reverse proxy sonlandırır (Caddy örneği):

```caddyfile
# /etc/caddy/Caddyfile  — ÖRNEK değerler
panel.example.internal {
    reverse_proxy /api/* 127.0.0.1:8000
    reverse_proxy *      127.0.0.1:3000
    header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    header X-Content-Type-Options "nosniff"
    header X-Frame-Options "DENY"
    header Referrer-Policy "no-referrer"
}
```

- Proxy TLS'i sonlandırıyorsa `HSTS_ENABLED=false` kalır (başlığı proxy yazar;
  çift başlık olmaz). Uygulama doğrudan HTTPS sunuyorsa `HSTS_ENABLED=true`.
- Wazuh Indexer'da TLS doğrulaması prod'da ZORUNLUDUR (`WAZUH_VERIFY_TLS=false`
  iken uygulama başlamaz). Self-signed CA: sertifikayı backend imajına güven
  olarak ekleyin (Dockerfile `COPY ca.crt /usr/local/share/ca-certificates/ &&
  update-ca-certificates`).
- Host güvenlik duvarı (nftables/ufw) önerisi:
  - `9200` (Indexer): yalnızca ajant host IP'sine izin ver (kaynak IP kısıtı).
  - `11434` (Ollama): dış dünyaya KAPALI; yalnızca loopback/docker bridge.
  - `8000/3000`: yalnızca loopback (proxy bağımlı) veya iç ağ.
  - `5432` (Postgres): host'ta HİÇBİR arayüze bağlı değil (compose `expose`).
- **Port taraması yalnızca YETKİLİ staging üzerinde** yapılmalıdır
  (`nmap -sT -p- <staging-ip>`); üretim verisi/secret kullanılmaz.

## 5. Log rotation

- **Konteynerler**: compose `logging` (json-file, `max-size: 10m`,
  `max-file: 3`) — her servis için yapılandırılmıştır.
- **Host systemd-proxy logları** (caddy/nginx): default journald rotasyonu veya
  `/etc/logrotate.d/` dosyası:
  ```
  /var/log/caddy/*.log {
      daily
      rotate 14
      compress
      missingok
      notifempty
  }
  ```
- Uygulama logları structlog JSON olarak stdout'a yazılır; credential taraması
  (Faz 07/08 smoke) parola/JWT sızmadiğini kanıtlar. Loglara parola yazan kod
  yolu yoktur (AGENTS.md §6).

## 6. İzleme ve disk dolması alarmı

- `/api/v1/ready` bileşenleri: `database`, `wazuh`, `ollama`, `disk`.
- `disk` bileşeni: boş yüzde `DISK_MIN_FREE_PERCENT` (varsayılan 10) altına
  inerse `low_space` döner + `disk_low_space` uyarı loglanır.
- İzleme cron örneği (host):

```bash
# /etc/cron.d/ajant-monitor — her 5 dakika
*/5 * * * * curl -sf http://127.0.0.1:8000/api/v1/ready | grep -q '"disk":"up"' || \
  /usr/local/bin/alert-ajant.sh "ready bileşeni düşük/low_space"
*/5 * * * * df --output=pcent -h /var/lib/docker/volumes/ajant_pgdata | tail -1 | \
  grep -qE '^[0-9]{2}%|^100%' || /usr/local/bin/alert-ajant.sh "pgdata disk %80+"
```

- `alert-ajant.sh` içeriği kuruma göre değişir (e-posta/webhook); bildirim
  entegrasyonu ürün yol haritasındadır (§Yol haritası).
- Retention: events tablosu `RETENTION_DAYS` (varsayılan 30) ile worker içinde
  temizlenir; disk büyümesinin kalıcı nedeni genellikle pgdata'dır.

## 7. Backup / restore (ve testi)

```bash
# Yedek (host'ta; umask 077; sıfır-bayt yedek hata sayılır)
./scripts/backup_db.sh ./backups --prune-days 30

# Restore testi (staging; MEVCUT VERİYİ SİLER — onay ister)
./scripts/restore_db.sh backups/ajant-YYYYMMDD-HHMMSS.dump
docker compose exec db psql -U ajant -c 'SELECT count(*) FROM events;'
curl -s http://127.0.0.1:8000/api/v1/ready | grep components
```

- Yedekleme sıklığı önerisi: günlük (cron) + kritik değişiklik öncesi.
- Faz 10 sertleştirmesi: başarısız koşumda yarım dump dosyası otomatik SİLİNİR
  (EXIT trap) — operatör "bozuk yedek var" sanıp restore denemesi yapamaz;
  geçerli yedek (TAMAM sonrası) trap kaldırıldığı için prune hatasında korunur.
- Restore testi staging'de AYLIK yinelenir (phases/08 test promptu: her test
  için komut/beklenen/gelen raporu — `docs/phase-08-verification.md`).

## 8. Upgrade prosedürü

```bash
cd ajant
git pull                                  # yeni sürüm kodu
./scripts/backup_db.sh ./backups          # ÖNCE yedek
docker compose build                      # imajları yeniden derle
docker compose up -d                      # backend başlangıcında alembic upgrade head
curl -s http://127.0.0.1:8000/api/v1/ready
```

- Migration'lar konteyner başlangıcında uygulanır; migration hatası konteyneri
  düşürür (sessiz yarım kurulum yok).
- Şema değişikliği içeren sürümlerde backend başlamazsa logları inceleyin
  (`docker compose logs backend`).

## 9. Rollback prosedürü

```bash
# 1) Önceki sürüme kod dönüşü
git checkout <önceki-tag>

# 2) Migration geri dönüşü (VERİ KAYBI OLABİLİR — önce yedek!)
docker compose stop backend
docker compose run --rm backend alembic downgrade <hedef-revision>
#    örnek: 0006_hardening geri: alembic downgrade 0005_remediation
#    NOT: downgrade öncesi RATE_LIMIT_BACKEND=database kullanılıyorsa
#    memory'e alın (tablo düşürüldükten sonra fren fail-closed olur).

# 3) Eski sürümü başlat
docker compose up -d --build backend

# 4) Veri bozulması şüphesi varsa yedekten restore:
./scripts/restore_db.sh backups/<öncesi>.dump
```

- Uygulama modu rollback'i: `POLICY_MODE` her zaman `observe_only` varsayılanına
  dönebilir (validator prod'da zorlar).
- Kill switch'ler: `REMEDIATION_ENABLED=false` (müdahale), `ANALYSIS_ENABLED=false`
  (analiz), `CORRELATION_ENABLED=false` (korelasyon) — anında devre dışı bırakma
  için restart yeterli.

## 10. Dependency ve secret taramaları

```bash
# Secret tarama (repo kökünde; git izlenen dosyalar)
./scripts/secret_scan.sh

# Python dependency zafiyet taraması (Faz 08'de çalıştırıldı: TEMİZ)
python3 -m pip install pip-audit
python3 -m pip_audit -r backend/requirements-lock.txt --no-deps --desc off

# Frontend dependency zafiyet taraması (Faz 08'de çalıştırıldı: TEMİZ)
cd frontend && npm audit && npm audit --omit=dev
```

- Bulgu çıktığında: fix sürümü varsa lock dosyasını güncelleyin (Faz 08'de
  pyjwt 2.12.1→2.15.1, starlette 0.50.0→1.3.1, fastapi 0.128.0→0.162.0,
  pydantic-settings 2.13.1→2.14.2, next 15.5.4→15.5.28, postcss override
  8.5.32, sharp fix bu gerekçeyle yapılmıştır), sonra TÜM test paketini koşun.
- İmaj digest pinleme: `docker images --digests` ile baz imaj digest'ini
  alın, Dockerfile'da `python:3.12-slim-bookworm@sha256:<digest>` biçiminde
  pinleyin (staging'de doğrulandıktan sonra).

## 11. Non-root ve minimum yetki

- Backend imajı `appuser` (uid 10001); frontend `node` kullanıcısı.
- Compose: `cap_drop: [ALL]` (backend/frontend), `no-new-privileges: true`
  (her servis), backend `read_only: true` + `tmpfs /tmp` (kalıcı yazma yalnızca
  DB biriminde).
- DB konteyneri default caps ile kalır (postgres CHOWN/SETUID/SETGID ister);
  `no-new-privileges` + iç ağ + port kapatması ile yetki yüzeyi sınırlıdır.

## 12. Yol haritası (Faz 08'de planlanan, kodu olmayan)

- **Bildirim entegrasyonu** (e-posta/webhook): `alert-ajant.sh` yerine panel
  içi bildirim ayarları; `NotificationSettings` şeması yer tutucudur (kod yolu
  yoktur). Önerilen sıra: 1) webhook (opsiyonel HMAC imza), 2) e-posta (SMTP),
  3) rate limit audit eylemine bağlama.
- **Redis rate limit deposu**: çok düğümlü dağıtımda `DatabaseRateLimiter`
  yerine Redis; mevcut arayüzle (async `check`) birebir değiştirilebilir.
- **Secret manager geçişi** (Docker secrets/vault) ve **imaj digest pinning**.
- **jti denylist**: GEREKMEZ — kullanıcı devre dışı bırakma tüm oturumları
  anında düşürür (DB aktiflik kontrolü her istekte); karar
  `docs/phase-08-verification.md` §mimari kararlar.

## 13. Incident runbook

Olay senaryoları ve adım adım müdahale prosedürleri:
**docs/incident-runbook.md** (disk dolması, DB down, brute-force saldırısı,
secret sızıntısı, admin kilitlenmesi, rollback).
