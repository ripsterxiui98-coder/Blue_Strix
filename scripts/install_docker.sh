#!/usr/bin/env bash
set -Eeuo pipefail

echo "[BlueStrix] Installing Docker"
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"

echo "[BlueStrix] Docker installed"
echo "Logout and login again to apply docker group"
