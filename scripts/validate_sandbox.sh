#!/usr/bin/env bash
set -Eeuo pipefail

echo "[BlueStrix] Validating sandbox"

docker compose config

echo "[BlueStrix] Checking Docker socket exposure"
if docker compose config | grep -q "/var/run/docker.sock"; then
  echo "ERROR: Docker socket exposed"
  exit 1
fi

echo "[BlueStrix] Checking privileged mode"
if docker compose config | grep -q "privileged: true"; then
  echo "ERROR: Privileged mode detected"
  exit 1
fi

echo "[BlueStrix] Sandbox validation passed"
