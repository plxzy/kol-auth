#!/bin/bash
# Deploy kol-auth to VPS
# Usage: ./deploy.sh

set -e

VPS_HOST="root@64.188.119.201"
VPS_PATH="/opt/kol-auth"
LOCAL_PATH="/Users/psp/Development/kol-auth"

echo "=== Deploying kol-auth to VPS ==="

# Sync files (exclude .git, build artifacts, etc.)
rsync -avz --delete \
  --exclude '.git' \
  --exclude '.gradle' \
  --exclude 'build' \
  --exclude 'node_modules' \
  --exclude '.idea' \
  --exclude '*.log' \
  "$LOCAL_PATH/" "$VPS_HOST:$VPS_PATH/"

echo ""
echo "=== Building on VPS ==="
ssh "$VPS_HOST" "cd $VPS_PATH && ./gradlew build -x test"

echo ""
echo "=== Restarting auth server ==="
ssh "$VPS_HOST" "pkill -f 'auth-server:run' 2>/dev/null; cd $VPS_PATH && ./gradlew :auth-server:run > /tmp/auth-server.log 2>&1 &"

echo ""
echo "✅ Deployed! Check logs: ssh $VPS_HOST 'tail -f /tmp/auth-server.log'"
