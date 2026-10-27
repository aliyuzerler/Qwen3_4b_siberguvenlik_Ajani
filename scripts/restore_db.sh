#!/usr/bin/env sh
# ajant — DB geri yükleme scripti (Faz 08)
#
# Kullanım:
#   ./scripts/restore_db.sh backups/ajant-YYYYMMDD-HHMMSS.dump
#
# ADIMLAR (güvenli sıra):
#   1) backend DURDURULUR (çalışırken restore = veri yarışı; asla yapma)
#   2) pg_restore --clean --if-exists (şema+veri, mevcut şema düşürülür)
#   3) backend yeniden başlatılır (migration'lar alembic version tablosuyla
#      uyumlu olduğundan upgrade head no-op döner)
#
# UYARI: --clean MEVCUT VERİYİ SİLER. Bu script yalnızca hedef ortamın
# YÖNETİCİSİ tarafından, yedek dosyası doğrulandıktan sonra çalıştırılmalıdır.
set -eu

DUMP="${1:-}"
if [ -z "$DUMP" ] || [ ! -f "$DUMP" ]; then
  echo "[restore_db] HATA: yedek dosyası gerekli (örn. backups/ajant-20260101-000000.dump)" >&2
  exit 2
fi

echo "[restore_db] UYARI: bu işlem mevcut veritabanını SİLER ve '$DUMP' ile değiştirir."
printf "Onaylıyor musunuz? (evet/hayır): "
read -r ANSWER
if [ "$ANSWER" != "evet" ]; then
  echo "[restore_db] iptal edildi."
  exit 1
fi

echo "[restore_db] 1/3 backend durduruluyor..."
docker compose stop backend

echo "[restore_db] 2/3 pg_restore --clean --if-exists çalıştırılıyor..."
docker compose exec -T db psql -U ajant -c "SELECT 1;" >/dev/null   # db hazır mı?
docker compose exec -T db pg_restore -U ajant --clean --if-exists --no-owner -d ajant < "$DUMP"

echo "[restore_db] 3/3 backend başlatılıyor..."
docker compose start backend

echo "[restore_db] TAMAM. Doğrulama önerisi:"
echo "  docker compose exec db psql -U ajant -c 'SELECT count(*) FROM events;'"
echo "  curl -s http://127.0.0.1:8000/api/v1/ready | grep components"
