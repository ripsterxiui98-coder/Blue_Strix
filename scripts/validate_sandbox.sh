#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE="docker-compose.yml"
POLICY="policies/SANDBOX_RULES.yaml"
VM_CONFIG="infra/firecracker/vm_config.json"

echo "== BlueStrix sandbox validation =="

if [ ! -f "$COMPOSE" ]; then
  echo "ERROR: $COMPOSE not found"
  exit 1
fi

if [ ! -f "$POLICY" ]; then
  echo "ERROR: $POLICY not found"
  exit 1
fi

if [ ! -f "$VM_CONFIG" ]; then
  echo "ERROR: $VM_CONFIG not found"
  exit 1
fi

# --- File-level security checks (always hard-fail) ---
if grep -E '/var/run/docker\.sock|docker\.sock' "$COMPOSE"; then
  echo "ERROR: Docker socket exposed in docker-compose.yml"
  exit 1
fi

if grep -E '^[[:space:]]*privileged:[[:space:]]*true' "$COMPOSE"; then
  echo "ERROR: Privileged mode detected in docker-compose.yml"
  exit 1
fi

if ! grep -qE 'user:[[:space:]]*["'\'']?10001:10001' "$COMPOSE"; then
  echo "ERROR: Scanner must run as non-root user 10001:10001"
  exit 1
fi

if ! grep -q 'network_mode: none' "$COMPOSE"; then
  echo "ERROR: Scanner must use network_mode: none"
  exit 1
fi

if ! grep -q 'read_only: true' "$COMPOSE"; then
  echo "ERROR: Scanner must use read_only: true"
  exit 1
fi

if ! grep -q 'cap_drop:' "$COMPOSE" || ! grep -q '\- ALL' "$COMPOSE"; then
  echo "ERROR: Scanner must drop all capabilities (cap_drop: ALL)"
  exit 1
fi

if ! grep -q 'no-new-privileges:true' "$COMPOSE"; then
  echo "ERROR: Scanner must set no-new-privileges:true"
  exit 1
fi

# --- Compose parse (best-effort) ---
export POSTGRES_USER="${POSTGRES_USER:-ci}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-ci}"
export POSTGRES_DB="${POSTGRES_DB:-ci}"
export REDIS_PASSWORD="${REDIS_PASSWORD:-ci}"

if command -v docker >/dev/null 2>&1; then
  if docker compose config >/dev/null 2>&1; then
    echo "docker compose config: OK"
  else
    echo "WARNING: docker compose config failed (missing images/env or syntax); file-level security checks passed"
  fi
else
  echo "docker not available; skipped compose config parse"
fi

# --- Firecracker JSON ---
if ! python3 -c "
import json, sys
from pathlib import Path
p = Path('$VM_CONFIG')
cfg = json.loads(p.read_text(encoding='utf-8'))
if cfg.get('network-interfaces') not in ([], None):
    print('ERROR: Firecracker network-interfaces must be empty')
    sys.exit(1)
mc = cfg.get('machine-config') or {}
if int(mc.get('vcpu_count', 99)) > 1:
    print('ERROR: Firecracker vcpu_count must be <= 1')
    sys.exit(1)
if int(mc.get('mem_size_mib', 9999)) > 512:
    print('ERROR: Firecracker mem_size_mib must be <= 512')
    sys.exit(1)
drives = cfg.get('drives') or []
root = [d for d in drives if d.get('drive_id') == 'rootfs']
if not root or not root[0].get('is_root_device'):
    print('ERROR: Firecracker rootfs drive missing or not root device')
    sys.exit(1)
print('Firecracker vm_config.json: OK')
"; then
  echo "ERROR: Firecracker configuration validation failed"
  exit 1
fi

echo "Sandbox validation passed"
