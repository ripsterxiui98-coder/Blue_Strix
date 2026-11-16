#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ -f .venv/bin/activate ] && source .venv/bin/activate
mkdir -p reports/junit reports/coverage
pytest tests/unit tests/security tests/regression -v \
  --junitxml=reports/junit/bluestrix-tests.xml \
  --cov=src/bluestrix --cov-report=term-missing \
  --cov-report=html:reports/coverage/html
