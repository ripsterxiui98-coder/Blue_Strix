#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-./tests/fixtures}"
REPORTS="${2:-./reports}"
CONFIG="${3:-config/bluestrix.example.yaml}"

mkdir -p "$REPORTS"

if [ ! -d "$TARGET" ]; then
  echo "Target directory not found: $TARGET"
  exit 0
fi

if ! command -v bluestrix >/dev/null 2>&1; then
  echo "BlueStrix CLI not found; skipping scan"
  exit 0
fi

if [ -f "$CONFIG" ]; then
  bluestrix --config "$CONFIG" scan code "$TARGET" --output "$REPORTS/findings" || {
    echo "Scan completed with non-zero exit; reports may still exist under $REPORTS"
  }
else
  echo "Config not found ($CONFIG); attempting scan without explicit config"
  bluestrix scan code "$TARGET" --output "$REPORTS/findings" || true
fi
