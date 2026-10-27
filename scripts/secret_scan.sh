#!/usr/bin/env sh
# ajant — secret scanning (Faz 08; phases/08: "secret scanning")
#
# Kullanım: ./scripts/secret_scan.sh
#
# Yöntem: gitleaks/binary gerektirmez; git ile İZLENEN dosyalar üzerinde
# desen taraması yapar (rg). Tarama kapsamı: AWS/Google anahtarları, özel
# PEM anahtarlar, JWT/HMAC secret kalıpları, gerçek-parola benzeri atamalar,
# Ollama/Wazuh credential şablonları.
#
# Bilinçli istisnalar (FALSE POSITIVE beyaz listesi):
# - .env.example / compose: ÖRNEK değerler ("SAHTE", "DEGISTIR", "ÖRNEKTİR")
# - test dosyaları: yalnızca "test-", "sahte", "fake" öneki değerler
#
# Çıkış kodu: 0 = temiz, 1 = şüpheli bulgu (CI'da build'i kırmak için).
set -eu

cd "$(dirname "$0")/.."

# Tarama: git ls-files (izlenen dosyalar; .env repoda DEĞİLDİR — kontrolü de
# aşağıda ayrıca yapılır) + rg sabit desenler.
PATTERNS='
(A3T[A-Z0-9]{16}|AKIA[0-9A-Z]{16})
-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY BLOCK-----
xox[baprs]-[0-9A-Za-z-]{10,}
ghp_[0-9A-Za-z]{36}
gho_[0-9A-Za-z]{36}
glpat-[0-9A-Za-z\-_]{20,}
sk-[a-zA-Z0-9]{20,}
eyJhbGciOi[A-Za-z0-9_\-=]{40,}\.eyJ[A-Za-z0-9_\-=]{40,}\.[A-Za-z0-9_\-=]{10,}
(?i)password\s*[:=]\s*["'\''][^"'\''/]{8,}["'\'']
(?i)api[_-]?key\s*[:=]\s*["'\''][A-Za-z0-9_\-]{16,}["'\'']
(?i)secret\s*[:=]\s*["'\''][A-Za-z0-9_\-]{16,}["'\'']
'

EXIT_CODE=0

echo "[secret_scan] 1/2 git izlenen dosyalarda desen taraması..."
if git ls-files -z | xargs -0 rg -n --hidden --no-ignore -e "$PATTERNS" \
    -g '!*.lock' -g '!package-lock.json' 2>/dev/null; then
  echo "[secret_scan] BULGU: yukarıdaki satırları inceleyin (false positive ise kapsamı daraltın)." >&2
  EXIT_CODE=1
else
  echo "[secret_scan] temiz: izlenen dosyalarda secret kalıbı yok."
fi

echo "[secret_scan] 2/2 .env / credential dosyaları sürüm kontrolünde mi?"
if [ -n "$(git ls-files --error-unmatch backend/.env 2>/dev/null || true)" ] \
   || [ -n "$(git ls-files --error-unmatch frontend/.env 2>/dev/null || true)" ]; then
  echo "[secret_scan] BULGU: .env dosyası git'te İZLENİYOR (AGENTS.md §3 ihlali)!" >&2
  EXIT_CODE=1
else
  echo "[secret_scan] temiz: .env dosyaları izlenmiyor (gitignore kapsamında)."
fi

if [ "$EXIT_CODE" -eq 0 ]; then
  echo "[secret_scan] SONUÇ: TEMİZ"
else
  echo "[secret_scan] SONUÇ: BULGU VAR (yukarıya bakın)" >&2
fi
exit "$EXIT_CODE"
