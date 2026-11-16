#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source .venv/bin/activate
mkdir -p reports/smoke
bluestrix --version
bluestrix --config config/bluestrix.example.yaml policy validate
bluestrix controls --output reports/smoke/control_findings
bluestrix scan code tests/fixtures --languages solidity python --output reports/smoke/code_scan
echo "Smoke tests passed"
