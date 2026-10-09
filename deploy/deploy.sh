#!/usr/bin/env bash
#
# deploy.sh - build frontend + (re)start backend untuk SecVal di VPS.
#
# Jalanin dari root repo di VPS:
#     bash deploy/deploy.sh
#
# Yang dilakuin:
#   1. Build frontend (via Docker) -> ambil folder dist
#   2. Copy dist ke /var/www/secval (yang di-serve nginx)
#   3. Build & up backend pakai docker-compose.prod.yml (bind 127.0.0.1:8000)
#   4. Reload nginx
#
# Ini TIDAK ngurus SSL. SSL dipasang sekali pakai certbot (lihat deploy/README.md).

set -euo pipefail

# --- Pindah ke root repo (parent dari folder deploy/) -----------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

WEBROOT="/var/www/secval"

echo "==> Repo: $REPO_ROOT"

# --- 1. Build frontend jadi static (via Docker, VPS ga perlu Node) ----------
echo "==> Build frontend..."
docker build -f frontend/Dockerfile.prod -t secval-frontend-build ./frontend

# --- 2. Extract dist dari image ke host, lalu copy ke webroot ---------------
echo "==> Ambil hasil build (dist)..."
TMP_DIST="$(mktemp -d)"
# Bikin container sementara dari image build, copy /dist keluar.
CID="$(docker create secval-frontend-build)"
docker cp "$CID:/dist/." "$TMP_DIST/"
docker rm "$CID" >/dev/null

echo "==> Deploy ke $WEBROOT..."
sudo mkdir -p "$WEBROOT"
# Hapus isi lama, ganti dengan build baru.
sudo rm -rf "${WEBROOT:?}/"*
sudo cp -r "$TMP_DIST/." "$WEBROOT/"
rm -rf "$TMP_DIST"

# --- 3. Build & up backend (prod compose) -----------------------------------
echo "==> Up backend (docker-compose.prod.yml)..."
docker compose -f docker-compose.prod.yml up -d --build

# --- 4. Reload nginx --------------------------------------------------------
echo "==> Test & reload nginx..."
sudo nginx -t
sudo systemctl reload nginx

echo ""
echo "==> Selesai."
echo "    Frontend: $WEBROOT"
echo "    Backend : http://127.0.0.1:8000 (via nginx /api/)"
echo "    Cek     : curl -I http://secval.my.id"
