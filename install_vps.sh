#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "[BlueStrix] Installing dependencies for VPS"
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git build-essential

echo "[BlueStrix] Creating virtual environment"
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip wheel setuptools
pip install -e ".[dev]"

echo "[BlueStrix] Creating local configuration"
if [ ! -f config/bluestrix.yaml ]; then
  cp config/bluestrix.example.yaml config/bluestrix.yaml
fi

echo "[BlueStrix] Generating test fixtures"
python scripts/generate_fixtures.py

echo "[BlueStrix] Installation complete"
echo "Activate environment with: source .venv/bin/activate"
echo "Run tests with: ./scripts/run_full_test_suite.sh"
