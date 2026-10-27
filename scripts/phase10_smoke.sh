#!/usr/bin/env bash
# Faz 10 uçtan uca operasyon smoke testi (phases/10-deployment-and-operations.md)
#
# Amaç: operatörün staging'de izleyeceği uçtan uca akışın SÖZLEŞMESİNİ sandbox'ta
# kanıtlamak (Docker/gerçek model olmadan; gerçek koşum komutları
# docs/phase-10-operations.md §12 NOT RUN listesinde).
#
# Evre 1 — İlk kurulum + health: temiz DB → alembic head → /health 200 →
#          /ready bileşenleri (wazuh: up [mock], ollama: down [kapalı port],
#          database: up, disk) + bootstrap admin girişi.
# Evre 2 — Test alert besleme (scripts/seed_staging_events.py): sentetik alert'ler
#          ÜRETİM ingest yoluyla (parse→normalize→redact→idempotent store) ŞİMDİ
#          zamanlı beslenir → 6 stored; tekrar koşum → 6 duplicate (idempotency).
#          Saat-bağımsızdır (fixture zaman damgaları tazelenir).
# Evre 3 — Model erişimi KESİK (kapalı port): gerçek uygulama + worker döngüsü →
#          altyapı hatası yolu: analyses tablosuna satır YAZILMAZ (analysis=None,
#          sahte değerlendirme yok), event'ler pending kalır, döngü ÇÖKMEZ
#          (worker_cycle_failed logu) ve süreç hizmet vermeye devam eder.
# Evre 4 — Model BOZUK ÇIKTI üretiyor (scripts/fake_ollama_server.py): /ready
#          ollama up olur; katı şema reddeder → retry → analysis_failed SATIRLARI
#          (güvenli fallback; AGENTS.md §5) — completed 0.
# Evre 5 — Wazuh kesintisi (indexer + ölü URL): /ready wazuh down, uygulama 200,
#          SAKLI olaylara erişim sürer (zarif düşüş).
# Evre 6 — Kill switch: ANALYSIS_ENABLED=false → /ready ollama: disabled.
# Evre 7 — Backup sözleşmesi: Docker'sız ortamda backup_db.sh fail-fast
#          (yarım dump ARTIĞI BIRAKMAZ) + restore_db.sh onay/argüman koruması.
#
# Tüm parolalar SAHTE smoke değeridir (AGENTS.md §3); veri sentetiktir.
set -euo pipefail
cd "$(dirname "$0")/../backend"

export JWT_SECRET="smoke-sadece-sahte-secret-0123456789abcdef-0123456789abcdef"
export DATABASE_URL="sqlite+aiosqlite:////tmp/ajant_phase10_smoke.db"
export ADMIN_BOOTSTRAP_PASSWORD="smoke-admin-parola-1234"
export OLLAMA_MODEL_TAG="qwen3:4b"
export LOG_LEVEL="INFO"   # döngü turu logları (worker_analysis_cycle) INFO'dur
export AUTH_RATE_LIMIT_PER_MINUTE="100"
# Döngü ayarları: ilk pencere kısıtı (≤86400) fixture'ları kaçırdığı için ingest
# Evre 2'deki üretim-yolu besleyiciyle yapılır; Evre 3/4'te kaynak YOK
# (indexer modu + boş URL → build_alert_source None → döngü ingest'i atlar).
export WORKER_INTERVAL_SECONDS="5"
export ANALYSIS_MAX_RETRIES="1"
export ANALYSIS_BACKOFF_BASE_SECONDS="0.2"
export WORKER_TIMEOUT_SECONDS="10"

B="http://127.0.0.1:8767"
pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS: $1 ($3)";
  else fail=$((fail+1)); echo "FAIL: $1 (beklenen $2, gelen $3)"; fi
}

start_uvicorn() { # $1: ek env (K=V K=V ...)
  # shellcheck disable=SC2086
  env $1 uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8767 \
    >/tmp/ajant10_uvicorn.log 2>&1 &
  UVPID=$!
  sleep 4
}
stop_uvicorn() { kill "$UVPID" 2>/dev/null || true; wait "$UVPID" 2>/dev/null || true; }

login() { curl -s -X POST $B/api/v1/auth/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}"; }
get_token() { login admin smoke-admin-parola-1234 | python3 -c \
  'import json,sys; print(json.load(sys.stdin).get("access_token",""))'; }

# ==================== EVRE 1: ilk kurulum + health ============================
echo "== EVRE 1: temiz kurulum, alembic, /health, /ready bileşenleri"
rm -f /tmp/ajant_phase10_smoke.db
python -m alembic upgrade head >/tmp/ajant10_alembic.log 2>&1
echo "== alembic head: $(tail -1 /tmp/ajant10_alembic.log)"

start_uvicorn "POLICY_MODE=observe_only WAZUH_SOURCE_MODE=mock OLLAMA_BASE_URL=http://127.0.0.1:9 ANALYSIS_ENABLED=true WORKER_LOOP_ENABLED=false"

check "/health 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' $B/api/v1/health)"
READY=$(curl -s $B/api/v1/ready)
check "ready: database up" "up" "$(echo "$READY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["components"]["database"])')"
check "ready: wazuh up (mock)" "up" "$(echo "$READY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["components"]["wazuh"])')"
check "ready: ollama down (kapalı port)" "down" "$(echo "$READY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["components"]["ollama"])')"
check "ready: disk raporlanır" "1" "$(echo "$READY" | python3 -c '
import json,sys
print(1 if json.load(sys.stdin)["components"].get("disk") in ("up","low_space","unknown") else 0)')"
check "bootstrap admin login" "1" "$([ -n "$(get_token)" ] && echo 1 || echo 0)"

stop_uvicorn

# ==================== EVRE 2: test alert besleme (üretim yolu) ================
echo "== EVRE 2: sentetik test alert besleme (idempotent ingest sözleşmesi)"
SEED1=$(python3 ../scripts/seed_staging_events.py --database-url "$DATABASE_URL")
check "besleme: 6 sentetik alert saklandı" "6" "$(echo "$SEED1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["stored"])')"
SEED2=$(python3 ../scripts/seed_staging_events.py --database-url "$DATABASE_URL")
check "tekrar besleme: YENİ SATIR YOK (idempotency_key tekil)" "0" "$(echo "$SEED2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["stored"])')"
check "tekrar besleme: tümü sınıflandı (duplicate+variant=6, taze damga=variant)" "6" "$(echo "$SEED2" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(d["duplicate"] + d.get("variant", 0))')"
check "tekrar besleme: hata yok" "0" "$(echo "$SEED2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["failed"])')"

# ==================== EVRE 3: model erişimi KESİK (altyapı yolu) ==============
echo "== EVRE 3: Ollama kapalı → pending kalır, sahte değerlendirme YAZILMAZ"
start_uvicorn "POLICY_MODE=observe_only WAZUH_SOURCE_MODE=indexer WAZUH_INDEXER_URL= WAZUH_INDEXER_USER= WAZUH_INDEXER_PASSWORD= OLLAMA_BASE_URL=http://127.0.0.1:9 ANALYSIS_ENABLED=true WORKER_LOOP_ENABLED=true"

sleep 9   # ilk tur (anında) + retry + 2. tur

TOKEN=$(get_token)
AUTH="Authorization: Bearer $TOKEN"
check "ready: ollama down" "down" "$(curl -s $B/api/v1/ready | python3 -c 'import json,sys; print(json.load(sys.stdin)["components"]["ollama"])')"
check "ready: wazuh not_configured (kaynak yok)" "not_configured" "$(curl -s $B/api/v1/ready | python3 -c 'import json,sys; print(json.load(sys.stdin)["components"]["wazuh"])')"
check "kesinti: olaylar saklı (6)" "6" "$(curl -s -H "$AUTH" "$B/api/v1/events?page_size=100" | python3 -c 'import json,sys; print(json.load(sys.stdin)["total"])')"
check "güvenli davranış: SAHTE değerlendirme YOK (analysis=None)" "6" "$(curl -s -H "$AUTH" "$B/api/v1/events?page_size=100" | python3 -c '
import json,sys
items=json.load(sys.stdin)["items"]
print(sum(1 for i in items if i["analysis"] is None))')"
check "dayanıklılık: döngü hatayı logladı, ÇÖKMEDİ" "1" "$(grep -q worker_cycle_failed /tmp/ajant10_uvicorn.log && echo 1 || echo 0)"
check "dayanıklılık: süreç hâlâ hizmet veriyor" "200" "$(curl -s -o /dev/null -w '%{http_code}' $B/api/v1/health)"

stop_uvicorn

# ==================== EVRE 4: model BOZUK çıktı (fallback yolu) ===============
echo "== EVRE 4: sahte Ollama (geçersiz çıktı) → analysis_failed güvenli fallback"
python3 ../scripts/fake_ollama_server.py --port 11450 >/tmp/ajant10_fake.log 2>&1 &
FAKEPID=$!
sleep 1
start_uvicorn "POLICY_MODE=observe_only WAZUH_SOURCE_MODE=indexer WAZUH_INDEXER_URL= WAZUH_INDEXER_USER= WAZUH_INDEXER_PASSWORD= OLLAMA_BASE_URL=http://127.0.0.1:11450 ANALYSIS_ENABLED=true WORKER_LOOP_ENABLED=true"

sleep 13  # ilk turda 6 pending → invalid JSON → retry → analysis_failed

check "ready: ollama up (düzeneği görüyor)" "up" "$(curl -s $B/api/v1/ready | python3 -c 'import json,sys; print(json.load(sys.stdin)["components"]["ollama"])')"
check "fallback: 6 olayda analysis_failed SATIRI" "6" "$(curl -s -H "$AUTH" "$B/api/v1/events?page_size=100" | python3 -c '
import json,sys
items=json.load(sys.stdin)["items"]
print(sum(1 for i in items if i["analysis"] is not None and i["analysis"]["status"]=="analysis_failed"))')"
check "fallback: uydurma 'completed' YOK" "0" "$(curl -s -H "$AUTH" "$B/api/v1/events?page_size=100" | python3 -c '
import json,sys
items=json.load(sys.stdin)["items"]
print(sum(1 for i in items if i["analysis"] is not None and i["analysis"]["status"]=="completed"))')"
check "döngü: analiz turu loglandı" "1" "$(grep -q worker_analysis_cycle /tmp/ajant10_uvicorn.log && echo 1 || echo 0)"
check "panel: /overview 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" $B/api/v1/overview)"
check "künye: model tag sabit" "qwen3:4b" "$(curl -s -H "$AUTH" $B/api/v1/overview | python3 -c 'import json,sys; print(json.load(sys.stdin)["model"]["model_tag"])')"
check "panel: /agents 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" $B/api/v1/agents)"
check "audit: başarılı giriş izi var" "1" "$(curl -s -H "$AUTH" "$B/api/v1/audit?page_size=100" | python3 -c '
import json,sys
rows=json.load(sys.stdin)["items"]
print(1 if any(r["action"]=="auth.login.success" for r in rows) else 0)')"
check "yetkisiz: events anonim 401" "401" "$(curl -s -o /dev/null -w '%{http_code}' "$B/api/v1/events")"

stop_uvicorn
kill "$FAKEPID" 2>/dev/null || true
wait "$FAKEPID" 2>/dev/null || true

# ==================== EVRE 5: Wazuh kesintisi =================================
echo "== EVRE 5: Wazuh down → zarif düşüş, saklı olaylara erişim sürer"
start_uvicorn "POLICY_MODE=observe_only WAZUH_SOURCE_MODE=indexer WAZUH_INDEXER_URL=http://127.0.0.1:9 WAZUH_INDEXER_USER=staging-ornek WAZUH_INDEXER_PASSWORD=sahte WAZUH_VERIFY_TLS=false ANALYSIS_ENABLED=false WORKER_LOOP_ENABLED=false"

TOKEN=$(get_token)
AUTH="Authorization: Bearer $TOKEN"
READY=$(curl -s $B/api/v1/ready)
check "ready: wazuh down" "down" "$(echo "$READY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["components"]["wazuh"])')"
check "ready: genel 200 (yalnız DB down 503'tür)" "200" "$(curl -s -o /dev/null -w '%{http_code}' $B/api/v1/ready)"
check "kesinti: saklı olaylara erişim SÜRÜYOR" "6" "$(curl -s -H "$AUTH" "$B/api/v1/events?page_size=100" | python3 -c 'import json,sys; print(json.load(sys.stdin)["total"])')"

stop_uvicorn

# ==================== EVRE 6: kill switch =====================================
echo "== EVRE 6: ANALYSIS_ENABLED=false → ollama bileşeni disabled"
start_uvicorn "POLICY_MODE=observe_only WAZUH_SOURCE_MODE=mock ANALYSIS_ENABLED=false WORKER_LOOP_ENABLED=false"

check "kill switch: /ready ollama disabled" "disabled" "$(curl -s $B/api/v1/ready | python3 -c 'import json,sys; print(json.load(sys.stdin)["components"]["ollama"])')"

stop_uvicorn

# ==================== EVRE 7: backup sözleşmesi ===============================
echo "== EVRE 7: backup/restore script sözleşmesi (Docker'sız fail-fast)"
cd ..
rm -rf /tmp/ajant10_backups && mkdir -p /tmp/ajant10_backups

BK_RC=0
./scripts/backup_db.sh /tmp/ajant10_backups >/tmp/ajant10_backup.log 2>&1 || BK_RC=$?
check "backup: docker'sız fail-fast (exit != 0)" "1" "$([ "$BK_RC" -ne 0 ] && echo 1 || echo 0)"
check "backup: yarım dump ARTIĞI YOK (trap temizliği)" "0" "$(find /tmp/ajant10_backups -name 'ajant-*.dump' 2>/dev/null | wc -l | tr -d ' ')"

touch /tmp/ajant10_fake.dump
RS_RC=0
printf 'hayır\n' | ./scripts/restore_db.sh /tmp/ajant10_fake.dump >/tmp/ajant10_restore.log 2>&1 || RS_RC=$?
check "restore: onaysız koşum reddedildi (exit 1)" "1" "$([ "$RS_RC" -eq 1 ] && echo 1 || echo 0)"
RS2_RC=0
./scripts/restore_db.sh >/tmp/ajant10_restore2.log 2>&1 || RS2_RC=$?
check "restore: argümansız çağrı exit 2" "1" "$([ "$RS2_RC" -eq 2 ] && echo 1 || echo 0)"

echo "==============================================="
echo "FAZ 10 SMOKE SONUCU: $pass PASS, $fail FAIL"
echo "==============================================="
[ "$fail" -eq 0 ]
