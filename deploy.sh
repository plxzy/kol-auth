#!/bin/bash
# Deploy kol-auth to VPS using Docker Compose
# Usage: ./deploy.sh [--build]

set -e

VPS_HOST="root@64.188.119.201"
VPS_PATH="/opt/kol-auth"
LOCAL_PATH="/Users/psp/Development/kol-auth"

BUILD_FLAG="${1:-}"

echo "=== Deploying kol-auth to VPS (Docker) ==="

# Sync files (exclude .git, build artifacts, etc.)
echo ""
echo "=== Syncing files to VPS ==="
rsync -avz --delete \
  --exclude '.git' \
  --exclude '.gradle' \
  --exclude 'build' \
  --exclude 'node_modules' \
  --exclude '.idea' \
  --exclude '*.log' \
  --exclude 'auth-server/build' \
  --exclude 'auth-core/build' \
  "$LOCAL_PATH/" "$VPS_HOST:$VPS_PATH/"

# Deploy via Docker Compose
echo ""
echo "=== Deploying with Docker Compose ==="
if [ "$BUILD_FLAG" == "--build" ]; then
  ssh "$VPS_HOST" "cd $VPS_PATH && docker compose up --build -d"
else
  ssh "$VPS_HOST" "cd $VPS_PATH && docker compose up -d"
fi

echo ""
echo "=== Health Check ==="
ssh "$VPS_HOST" "docker ps --filter 'name=kol-auth' --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"

echo ""
echo "✅ Deployed!"
echo "View logs: ssh $VPS_HOST 'cd $VPS_PATH && docker compose logs -f auth-server'"
