#!/usr/bin/env sh
# ajant — DB yedekleme scripti (Faz 08; phases/08: "DB backup/restore testi")
#
# Kullanım:
#   ./scripts/backup_db.sh [backups_dir] [--prune-days N]
#
# Varsayılan: ./backups dizinine timestamps'li pg_dump custom format (-Fc)
# dosyası yazar. --prune-days verilirse eski yedekleri siler.
#
# NOT: Bu script HOST makinede çalışır (docker compose erişimi gerekir).
# Sırlar: pg_dump container içinden ajant kullanıcısıyla çalışır; parola
# compose env'inden okunur, scriptte SAKLANMAZ. Yedek dosyası VERİ İÇERİR:
# izinleri kısıtlayın (script umask 077 uygular) ve yedek dizinini şifreli
# birimde tutun (docs/deployment.md §backup).
set -eu

BACKUPS_DIR="${1:-./backups}"
PRUNE_DAYS=""

# --- argümanlar: [dir] [--prune-days N] ------------------------------------
prev_was_prune=0
for arg in "$@"; do
  if [ "$prev_was_prune" = "1" ]; then
    PRUNE_DAYS="$arg"
    prev_was_prune=0
    continue
  fi
  if [ "$arg" = "--prune-days" ]; then
    prev_was_prune=1
  fi
done

umask 077
mkdir -p "$BACKUPS_DIR"

STAMP="$(date -u +%Y%m%d-%H%M%S)"
TARGET="$BACKUPS_DIR/ajant-$STAMP.dump"

echo "[backup_db] pg_dump (custom format) → $TARGET"
docker compose exec -T db pg_dump -U ajant -Fc ajant > "$TARGET"

# Sıfır baytlık yedek = başarısız yedek (sessiz kabul yok)
SIZE="$(wc -c < "$TARGET" | tr -d ' ')"
if [ "$SIZE" -lt 200 ]; then
  echo "[backup_db] HATA: yedek dosyası beklenenden küçük ($SIZE bayt) — pg_dump çökmüş olabilir." >&2
  exit 1
fi

# Archive bütünlüğü (Faz 08 bağımsız doğrulama F6): pg_restore -l dump
# katalogunu okuyabilirse dosya kesik/karışmış değildir (kısmi dump koruması).
if ! docker compose exec -T db pg_restore -U ajant -l /dev/stdin < "$TARGET" >/dev/null 2>&1; then
  echo "[backup_db] HATA: yedek archive doğrulaması (pg_restore -l) başarısız — dosya bozuk olabilir." >&2
  exit 1
fi

echo "[backup_db] TAMAM: $TARGET ($SIZE bayt, archive doğrulandı)"

if [ -n "$PRUNE_DAYS" ]; then
  echo "[backup_db] eski yedekler temizleniyor (>${PRUNE_DAYS} gün)"
  find "$BACKUPS_DIR" -name "ajant-*.dump" -type f -mtime "+$PRUNE_DAYS" -print -delete
fi

# Geri yükleme: scripts/restore_db.sh
# Doğrulama (restore testi): docs/deployment.md §backup/restore
