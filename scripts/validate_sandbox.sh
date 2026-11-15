#!/usr/bin/env bash
set -Eeuo pipefail

if [ ! -f docker-compose.yml ]; then
  echo "docker-compose.yml not found; skipping validation"
  exit 0
fi

docker compose config

if docker compose config | grep -q "/var/run/docker.sock"; then
  echo "ERROR: Docker socket exposed"
  exit 1
fi

if docker compose config | grep -q "privileged: true"; then
  echo "ERROR: Privileged mode detected"
  exit 1
fi

echo "Sandbox validation passed"
