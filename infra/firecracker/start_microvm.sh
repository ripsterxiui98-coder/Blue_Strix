#!/usr/bin/env bash
set -Eeuo pipefail

API_SOCKET="/tmp/firecracker.socket"
VM_ID="$(date +%s)"

echo "[BlueStrix] Starting Firecracker microVM: $VM_ID"

sudo rm -f "$API_SOCKET"

sudo /usr/local/bin/firecracker \
  --api-sock "$API_SOCKET" \
  --id "$VM_ID" &

sleep 2

curl --unix-socket "$API_SOCKET" \
  -X PUT "http://localhost/boot-source" \
  -H "Content-Type: application/json" \
  -d @infra/firecracker/vm_config.json

curl --unix-socket "$API_SOCKET" \
  -X PUT "http://localhost/actions" \
  -H "Content-Type: application/json" \
  -d '{"action_type":"InstanceStart"}'

echo "[BlueStrix] MicroVM started"
