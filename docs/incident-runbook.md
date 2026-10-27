# ajant — Incident Runbook (Faz 08)

Amaç: operatörün sık olay senaryolarında adım adım, doğrulanabilir müdahalesi.
İlkeler (AGENTS.md §2): güvenlik önce; iz bozulmaz; yıkıcı işlem önce yedek.

Acil durdurma anahtarları (her senaryoda tekrar kullanılır):

| Anahtar | Etki | Uygulama |
|---|---|---|
| `REMEDIATION_ENABLED=false` | Öneri+yürütme 503 | backend/.env + `docker compose up -d backend` |
| `ANALYSIS_ENABLED=false` | Analiz döngüsü disabled | aynı |
| `CORRELATION_ENABLED=false` | Korelasyon tespiti durur | aynı |
| `WORKER_LOOP_ENABLED=false` | Tüm arka plan döngüsü kapalı (varsayılan) | aynı |

---

## 1. Disk dolması (`/ready` disk: low_space)

**Belirti**: `/api/v1/ready` → `components.disk == "low_space"`; logda
`disk_low_space`.

```bash
# 1) Yer kaybının kaynağını bul
docker system df
du -sh /var/lib/docker/volumes/ajant_pgdata/_data
docker compose logs --tail 200 backend | head   # log birimi mi?

# 2) Güvenli temizlik
docker system prune -f                # kullanılmayan imaj/katmanlar
find ./backups -name 'ajant-*.dump' -mtime +30 -delete   # eski yedekler

# 3) pgdata büyüyorsa: retention süresini gözden geçir (RETENTION_DAYS)
#    ve manuel temizlik GEREKMEZ — worker kendi turlarında siler.

# 4) Eşik uyarısı kalıcıysa: DISK_MIN_FREE_PERCENT'i gerçek kapasiteye göre ayarla
```

**Yapılmaması gereken**: audit_log veya log dosyalarını elle silmek
(iz bütünlüğü; AGENTS.md §4).

## 2. Veritabanı down (`/ready` database: down)

**Belirti**: `/ready` 503; panel tüm sayfalarda hata.

```bash
docker compose ps db                       # konteyner ayakta mı?
docker compose logs --tail 100 db
docker compose restart db
curl -s http://127.0.0.1:8000/api/v1/ready # tekrar 200 mü?

# Veri bozulması şüphesi: en son yedekten restore (YIKICI — onay ister)
./scripts/backup_db.sh ./backups           # önce MEVCUT durumu yedekle (adli analiz için)
./scripts/restore_db.sh backups/<son-sağlıklı>.dump
```

## 3. Brute-force saldırısı (audit'te `auth.login.failed` patlaması)

**Belirti**: audit log'da tek IP'den yüksek hacimli `auth.login.failed`;
`auth.login.rate_limited` kayıtları.

```bash
# 1) Saldırganı audit'ten tespit et (admin paneli: /audit)
docker compose exec db psql -U ajant -c "
  SELECT client_ip, count(*) FROM audit_log
  WHERE action='auth.login.failed' AND created_at > now() - interval '1 hour'
  GROUP BY client_ip ORDER BY count DESC LIMIT 10;"

# 2) Rate limit zaten frenler (429). Kaynak host güvenlik duvarında blokla:
#    nft add rule inet filter input ip saddr <SALDIRGAN_IP> drop

# 3) Tavanı düşür (gerekirse): AUTH_RATE_LIMIT_PER_MINUTE=5 + restart

# 4) Başarılı şüpheli giriş varsa (auth.login.success + bilinmeyen IP):
#    - kullanıcıyı devre dışı bırak (panel: Kullanıcılar → Devre dışı bırak)
#      → token'ları ANINDA ölür (DB aktiflik kontrolü)
#    - parolayı admin resetle (/users/{id}/password), kullanıcıyı etkinleştir
```

## 4. Secret sızıntısı şüphesi (JWT_SECRET / parola / .env)

```bash
# 1) Sızıntı kaynağını tespit ve kapat (git geçmişi, log, dosya izinleri)
chmod 600 backend/.env
./scripts/secret_scan.sh

# 2) JWT_SECRET rotasyonu → tüm token'lar geçersizleşir (zorla çıkış):
#    backend/.env: JWT_SECRET=$(openssl rand -hex 32)
docker compose up -d backend

# 3) TÜM kullanıcı parolalarını sıfırla (admin route ile; sırayla) veya
#    bootstrap parolasını değiştirip kullanıcıları yeniden oluştur.
# 4) Olayı audit'e not düş: elle eklenen kayıt YOK — bu runbook'un kullanımı
#    incident kaydında (kurum süreci) belgelenir.
```

## 5. Admin kilitlenmesi (tüm adminler devre dışı / parola kaybı)

Backend'e host erişimi ile çözülür:

```bash
docker compose exec db psql -U ajant -c \
  "UPDATE users SET is_active=true WHERE username='admin';"
# Parola kaybı: bootstrap parolası users DOLU olduğunda işlemez (güvenlik);
# reset doğrudan DB'de hash ile:
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
        u = await s.get(User, *(await s.execute(__import__('sqlalchemy').select(User).where(User.username=='admin')))).scalars().first(),
    # NOT: yukarıdaki tek satır yerine:
    # from sqlalchemy import select
    # user = (await s.execute(select(User).where(User.username=='admin'))).scalars().first()
    # user.password_hash = hash_password("YENI-GUCLU-PAROLA-degistir")
    await engine.dispose()
asyncio.run(main())
PY
```

Dikkat: `hash_password` argon2id üretir; düz metin ASLA DB'ye yazılmaz.

## 6. Model/Ollama arızası (`/ready` ollama: down veya model_missing)

```bash
systemctl status ollama || pgrep -a ollama
ollama list                     # qwen3:4b kurulu mu?
ollama pull qwen3:4b            # model_missing → pull
# down: Ollama servisi kapalı/loglarına bak; backend'in OLLAMA_BASE_URL'i
# doğru host'u işaret ediyor mu? (compose: host.docker.internal:11434)
```

Analiz durumu: `ANALYSIS_ENABLED` açıksa döngü kendi dayanıklılığıyla bekler;
event'lere SAHTE değerlendirme YAZILMAZ (mock yolu kodda yoktur).

## 7. Sürüm geri alma (rollback)

Adım adım prosedür: **docs/deployment.md §9 Rollback**. Kısa özet:
yedek al → `git checkout <önceki-tag>` → gerekiyorsa `alembic downgrade
<hedef>` → `docker compose up -d --build` → `/ready` doğrula.

## 8. Müdahale eylemi yan etkisi (dry-run sonrası istenmeyen durum)

Dry-run yürütme SİSTEM DEĞİŞİKLİĞİ YAPMAZ (DryRunExecutor; simulated=true) —
gerçek yan etkisi olmaz. Gerçek sistem değişikliği gerektiren yürütücü
entegrasyonu KODDA YOKTUR; böyle bir kod eklendiğinde bu runbook ayrı bir
geri-alma (rollback_note) prosedürü ister (docs/remediation-runbook.md §6).

## 9. Şüpheli audit/log değişikliği

ajant audit_log'a YALNIZCA INSERT yazar; UPDATE/DELETE kod yolu yoktur
(testle kalıcı). Elle DB müdahalesi şüphesi:

```bash
docker compose exec db psql -U ajant -c "
  SELECT id, created_at, actor, action FROM audit_log
  WHERE created_at > now() - interval '24 hours' ORDER BY created_at DESC;"
```

DB erişim izni olan herkesin host yetkisi denetlenmelidir; DB'ye direkt yazma
yetkisi yalnızca yönetici hesabında olmalı (AGENTS.md §4: ajan kendi kayıtlarını
değiştiremez — bu garanti kod katmanında kalır).
