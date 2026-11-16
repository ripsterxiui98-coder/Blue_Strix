#!/usr/bin/env bash
set -Eeuo pipefail

echo "[BlueStrix] Installing Firecracker"
sudo apt update
sudo apt install -y curl jq

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) FC_ARCH="x86_64" ;;
  aarch64) FC_ARCH="aarch64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

RELEASE_URL="https://github.com/firecracker-microvm/firecracker/releases/latest/download/firecracker-v1.7.0-${FC_ARCH}.tgz"

curl -L "$RELEASE_URL" -o /tmp/firecracker.tgz
sudo mkdir -p /usr/local/bin
sudo tar -xzf /tmp/firecracker.tgz -C /tmp
sudo cp /tmp/firecracker-v1.7.0-${FC_ARCH}/firecracker /usr/local/bin/
sudo chmod +x /usr/local/bin/firecracker

echo "[BlueStrix] Firecracker installed"
echo "Check KVM: ls -l /dev/kvm"
