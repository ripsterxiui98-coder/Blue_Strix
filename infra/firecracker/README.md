# Firecracker MicroVM Sandbox

Firecracker digunakan untuk menjalankan kode tidak tepercaya.

## Requirement

- Linux VPS dengan KVM.
- Akses `/dev/kvm`.
- Kernel Linux.
- Rootfs image.
- Firecracker binary.

## Instalasi

./scripts/install_firecracker.sh

## Menjalankan scan

./scripts/run_microvm_scan.sh ./target-repo

## Catatan

Firecracker tidak cocok untuk Termux karena membutuhkan KVM.
