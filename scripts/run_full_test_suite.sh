#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source .venv/bin/activate
mkdir -p reports/junit reports/coverage reports/smoke
pytest tests/unit tests/security tests/regression -v \
  --junitxml=reports/junit/bluestrix-tests.xml \
  --cov=src/bluestrix --cov-report=term-missing \
  --cov-report=html:reports/coverage/html
bluestrix controls --output reports/smoke/control_findings
bluestrix scan code tests/fixtures --languages solidity python --output reports/smoke/code_scan
echo "Full test suite passed"
