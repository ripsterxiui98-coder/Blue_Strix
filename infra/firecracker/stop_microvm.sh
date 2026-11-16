#!/usr/bin/env bash
set -Eeuo pipefail

API_SOCKET="/tmp/firecracker.socket"

echo "[BlueStrix] Stopping Firecracker microVM"

curl --unix-socket "$API_SOCKET" \
  -X PUT "http://localhost/actions" \
  -H "Content-Type: application/json" \
  -d '{"action_type":"SendCtrlAltDel"}' || true

sleep 2

sudo pkill -f firecracker || true
sudo rm -f "$API_SOCKET"

echo "[BlueStrix] MicroVM stopped"
