#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-./tests/fixtures}"
REPORTS="${2:-./reports}"

mkdir -p "$REPORTS"

if [ ! -d "$TARGET" ]; then
  echo "Target directory not found: $TARGET"
  exit 1
fi

if command -v bluestrix >/dev/null 2>&1; then
  bluestrix scan code "$TARGET" --output "$REPORTS/findings"
else
  echo "BlueStrix CLI not found; skipping scan"
fi
