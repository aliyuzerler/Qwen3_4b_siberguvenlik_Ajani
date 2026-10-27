#!/usr/bin/env bash
# Faz 08 canlı smoke testi: uvicorn + sqlite + üç evre.
#
# Evre A (varsayılan): güvenlik başlıkları, gövde limiti (413), kullanıcı
#   yönetimi API akışları (RBAC, parola değiştirme/sıfırlama, kilit korumaları),
#   disk bileşeni, brute-force 429.
# Evre B (HSTS + DB fren): HSTS başlığı, RATE_LIMIT_BACKEND=database
#   (paylaşımlı sayaç satırları DB'ye yazılır).
# Evre C (prod matrisi): APP_ENV=prod → /docs kapalı; geçersiz prod config
#   (dry_run, localhost CORS, WAZUH_VERIFY_TLS=false) başlangıçta ÇÖKER.
#
# Tüm parolalar SAHTE smoke değeridir (AGENTS.md §3); veri sentetiktir.
set -euo pipefail
cd /home/z/my-project/ajant/backend

export JWT_SECRET="smoke-sadece-sahte-secret-0123456789abcdef-0123456789abcdef"
export DATABASE_URL="sqlite+aiosqlite:////tmp/ajant_phase08_smoke.db"
export WAZUH_SOURCE_MODE="mock"
export ADMIN_BOOTSTRAP_PASSWORD="smoke-admin-parola-1234"
export OLLAMA_BASE_URL="http://127.0.0.1:9"
export ANALYSIS_ENABLED="false"
export WORKER_LOOP_ENABLED="false"
export LOG_LEVEL="WARNING"

rm -f /tmp/ajant_phase08_smoke.db
python -m alembic upgrade head >/tmp/ajant08_alembic.log 2>&1
echo "== alembic head: $(tail -1 /tmp/ajant08_alembic.log)"

B="http://127.0.0.1:8766"
pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS: $1 ($3)";
  else fail=$((fail+1)); echo "FAIL: $1 (beklenen $2, gelen $3)"; fi
}
hdr() { curl -s -o /dev/null -w "%header{$1}" "$B/api/v1/health"; }

start_uvicorn() { # $1: extra env string (K=V K=V ...)
  # shellcheck disable=SC2086
  env $1 uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8766 \
    >/tmp/ajant08_uvicorn.log 2>&1 &
  UVPID=$!
  sleep 4
}
stop_uvicorn() { kill "$UVPID" 2>/dev/null || true; wait "$UVPID" 2>/dev/null || true; }

login() { curl -s -X POST $B/api/v1/auth/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}"; }

# ============================ EVRE A: hardening ===============================
echo "== EVRE A: güvenlik başlıkları + kullanıcı yönetimi + brute-force freni"
start_uvicorn "POLICY_MODE=observe_only MAX_REQUEST_BODY_BYTES=1024"

check "/health 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' $B/api/v1/health)"

# --- Güvenlik başlıkları (Faz 08) ---
check "X-Content-Type-Options: nosniff" "nosniff" "$(hdr x-content-type-options)"
check "X-Frame-Options: DENY" "DENY" "$(hdr x-frame-options)"
check "Referrer-Policy: no-referrer" "no-referrer" "$(hdr referrer-policy)"
check "Cache-Control: no-store" "no-store" "$(hdr cache-control)"
check "CSP default-src 'none'" "1" "$(case "$(hdr content-security-policy)" in *"default-src 'none'"*) echo 1;; *) echo 0;; esac)"
check "HSTS varsayılan YOK" "" "$(hdr strict-transport-security)"

# --- Gövde limiti (413): 2 KB parola alanı ---
BIG=$(python3 -c "print('x'*2048)")
check "oversized gövde 413" "413" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/auth/login \
  -H 'Content-Type: application/json' -d "{\"username\":\"a\",\"password\":\"$BIG\"}")"

# --- /ready disk bileşeni (Faz 08) ---
READY=$(curl -s $B/api/v1/ready)
check "/ready disk bileşeni var" "1" "$(echo "$READY" | python3 -c '
import json,sys
d=json.load(sys.stdin)["components"]
print(1 if d.get("disk") in ("up","low_space","unknown") else 0)')"

# --- Kullanıcı yönetimi akışları ---
TOKEN=$(login admin smoke-admin-parola-1234 | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
AUTH="Authorization: Bearer $TOKEN"
check "admin login" "1" "$([ -n "$TOKEN" ] && echo 1 || echo 0)"

check "viewer oluştur 201" "201" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/users \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"username":"viewer-smoke","password":"guclu-viewer-parola-1","role":"viewer"}')"
check "zayıf parola 422" "422" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/users \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"username":"weak-smoke","password":"kisa-123","role":"viewer"}')"

VLOGIN=$(login viewer-smoke guclu-viewer-parola-1)
VTOKEN=$(echo "$VLOGIN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
VAUTH="Authorization: Bearer $VTOKEN"
check "viewer login" "1" "$([ -n "$VTOKEN" ] && echo 1 || echo 0)"
check "viewer /users 403" "403" "$(curl -s -o /dev/null -w '%{http_code}' $B/api/v1/users -H "$VAUTH")"
check "anonim /users 401" "401" "$(curl -s -o /dev/null -w '%{http_code}' $B/api/v1/users)"

check "viewer yanlış önbilgi 400" "400" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/users/me/password \
  -H "$VAUTH" -H 'Content-Type: application/json' \
  -d '{"current_password":"YANLIS-parola","new_password":"viewer-yeni-parola-22"}')"
check "viewer parola değiştir 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/users/me/password \
  -H "$VAUTH" -H 'Content-Type: application/json' \
  -d '{"current_password":"guclu-viewer-parola-1","new_password":"viewer-yeni-parola-22"}')"
check "eski parola artık 401" "401" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"viewer-smoke","password":"guclu-viewer-parola-1"}')"
check "yeni parola login 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"viewer-smoke","password":"viewer-yeni-parola-22"}')"

USER_ID=$(curl -s $B/api/v1/users -H "$AUTH" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print([u["id"] for u in d["items"] if u["username"]=="viewer-smoke"][0])')
ADMIN_ID=$(curl -s $B/api/v1/auth/me -H "$AUTH" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

check "admin self-sıfırlama 409" "409" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/users/$ADMIN_ID/password \
  -H "$AUTH" -H 'Content-Type: application/json' -d '{"new_password":"admin-yeni-parola-33"}')"
check "admin viewer parolası sıfırlar 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/users/$USER_ID/password \
  -H "$AUTH" -H 'Content-Type: application/json' -d '{"new_password":"sifirli-viewer-parola-44"}')"
check "sıfırlanan parola login 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"viewer-smoke","password":"sifirli-viewer-parola-44"}')"

check "admin self-disable 409" "409" "$(curl -s -o /dev/null -w '%{http_code}' -X PATCH $B/api/v1/users/$ADMIN_ID \
  -H "$AUTH" -H 'Content-Type: application/json' -d '{"is_active":false}')"
check "son admin demote 409" "409" "$(curl -s -o /dev/null -w '%{http_code}' -X PATCH $B/api/v1/users/$ADMIN_ID \
  -H "$AUTH" -H 'Content-Type: application/json' -d '{"role":"viewer"}')"

# Devre dışı bırakma: token anında ölür, login reddedilir
check "viewer disable 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' -X PATCH $B/api/v1/users/$USER_ID \
  -H "$AUTH" -H 'Content-Type: application/json' -d '{"is_active":false}')"
VTOKEN2=$(login viewer-smoke sifirli-viewer-parola-44 | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))')
check "pasif hesap login edemez" "" "$VTOKEN2"

stop_uvicorn

# --- Brute-force freni (bellek içi): tavan 3 → 4. deneme 429 ---
echo "== EVRE A2: AUTH_RATE_LIMIT_PER_MINUTE=3 ile brute-force freni"
start_uvicorn "POLICY_MODE=observe_only AUTH_RATE_LIMIT_PER_MINUTE=3"
for _ in 1 2 3; do
  curl -s -o /dev/null -X POST $B/api/v1/auth/login \
    -H 'Content-Type: application/json' -d '{"username":"admin","password":"yanlis"}' >/dev/null
done
RL=$(curl -s -o /dev/null -w '%{http_code}' -D /tmp/ajant08_rl_headers.txt -X POST $B/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"yanlis"}')
RA=$(grep -i '^retry-after:' /tmp/ajant08_rl_headers.txt | tr -dc '0-9')
check "brute-force 429" "429" "$RL"
check "Retry-After başlığı var" "1" "$([ -n "$RA" ] && echo 1 || echo 0)"
stop_uvicorn

# ====================== EVRE B: HSTS + DB fren deposu =========================
echo "== EVRE B: HSTS_ENABLED=true + RATE_LIMIT_BACKEND=database"
start_uvicorn "POLICY_MODE=observe_only HSTS_ENABLED=true RATE_LIMIT_BACKEND=database AUTH_RATE_LIMIT_PER_MINUTE=2"
check "HSTS başlığı var" "max-age=31536000; includeSubDomains" "$(hdr strict-transport-security)"
TOKEN_B=$(login admin smoke-admin-parola-1234 | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
check "DB fren: admin login 1" "1" "$([ -n "$TOKEN_B" ] && echo 1 || echo 0)"
check "DB fren: 2. login 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"smoke-admin-parola-1234"}')"
check "DB fren: 3. deneme 429" "429" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"smoke-admin-parola-1234"}')"
stop_uvicorn

DBROWS=$(DATABASE_URL="$DATABASE_URL" python3 -c "
import sqlite3
conn = sqlite3.connect('/tmp/ajant_phase08_smoke.db')
n = conn.execute('SELECT count(*) FROM rate_limit_counters').fetchone()[0]
print(n if n > 0 else 0)")
check "rate_limit_counters satırları DB'de" "1" "$([ "$DBROWS" -gt 0 ] && echo 1 || echo 0)"

# ========================== EVRE C: prod matrisi ==============================
echo "== EVRE C: APP_ENV=prod matrisi"
# NOT: prod validator'ı üretimde WAZUH_SOURCE_MODE=mock'u YASAKLAR (Faz 01
# kuralı) → prod evresinde indexer modu verilir; URL yok → not_configured.
start_uvicorn "APP_ENV=prod POLICY_MODE=observe_only CORS_ORIGINS=https://panel.example.internal WAZUH_SOURCE_MODE=indexer"
check "prod /docs 404" "404" "$(curl -s -o /dev/null -w '%{http_code}' $B/docs)"
check "prod /openapi.json 404" "404" "$(curl -s -o /dev/null -w '%{http_code}' $B/openapi.json)"
check "prod /health 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' $B/api/v1/health)"
stop_uvicorn

prod_fails_to_start() { # $1: name, $2..: env
  local NAME="$1"; shift
  # shellcheck disable=SC2086
  env "$@" uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8766 \
    >/tmp/ajant08_prod_fail.log 2>&1 &
  local PID=$!
  sleep 5
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true
    check "prod red: $NAME (çökmez)" "çöker" "çökmez"
  else
    check "prod red: $NAME" "çöker" "çöker"
  fi
}
prod_fails_to_start "prod+dry_run" APP_ENV=prod POLICY_MODE=dry_run CORS_ORIGINS=https://panel.example.internal
prod_fails_to_start "prod+localhost-CORS" APP_ENV=prod CORS_ORIGINS=http://localhost:3000
prod_fails_to_start "prod+TLS-doğrulama-kapalı" APP_ENV=prod CORS_ORIGINS=https://panel.example.internal WAZUH_VERIFY_TLS=false

# ============================ SONUÇ ===========================================
echo ""
echo "SMOKE SONUÇ: $pass PASS, $fail FAIL"
[ "$fail" -eq 0 ]
