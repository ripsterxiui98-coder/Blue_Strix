#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-./target}"
REPORTS="${2:-./reports}"

mkdir -p "$REPORTS"

docker compose run --rm \
  -v "$(pwd)/$TARGET:/workspace:ro" \
  -v "$(pwd)/$REPORTS:/reports" \
  bluestrix-scanner \
  bluestrix scan code /workspace --output /reports/findings
