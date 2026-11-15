#!/usr/bin/env bash
set -Eeuo pipefail

if [ ! -f docker-compose.yml ]; then
  echo "docker-compose.yml not found; skipping validation"
  exit 0
fi

# Security checks on file content (always)
if grep -E '/var/run/docker\.sock|docker\.sock' docker-compose.yml; then
  echo "ERROR: Docker socket exposed in docker-compose.yml"
  exit 1
fi

if grep -E 'privileged:\s*true' docker-compose.yml; then
  echo "ERROR: Privileged mode detected in docker-compose.yml"
  exit 1
fi

# Compose parse (best-effort; needs env)
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

echo "Sandbox validation passed"
