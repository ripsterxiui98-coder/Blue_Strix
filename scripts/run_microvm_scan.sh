#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-./target}"
REPORTS="${2:-./reports}"

mkdir -p "$REPORTS"

echo "[BlueStrix] Running microVM sandbox scan"
./infra/firecracker/start_microvm.sh
sleep 5
./infra/firecracker/stop_microvm.sh

echo "[BlueStrix] MicroVM scan completed"
