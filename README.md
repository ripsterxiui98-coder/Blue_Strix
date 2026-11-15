# BlueStrix v8.0

BlueStrix adalah platform keamanan blockchain dan Web3 yang bersifat **defensif, evidence-based, dan read-only secara default**.

BlueStrix membantu:

- Menganalisis source code dan smart contract.
- Mendeteksi pola berisiko pada Solidity, Python, Rust, Move, dan TypeScript.
- Memvalidasi wallet address EVM dan Solana.
- Melakukan inspeksi read-only terhadap EVM dan Solana RPC.
- Menjalankan security controls, audit trail, dan threat correlation.
- Menghasilkan laporan JSON, Markdown, JUnit, dan coverage.
- Membuat **remediation proposal/patch** yang wajib disetujui pemilik kode sebelum diterapkan.

BlueStrix **tidak** melakukan eksploitasi, transfer aset, signing transaksi, deployment, atau perubahan state blockchain tanpa otorisasi manusia yang eksplisit.

## Fitur v8.0

- Policy engine dan Security Constitution.
- Scope authorization deny-by-default.
- Audit log append-only.
- Static code intelligence multi-language.
- Slither adapter untuk Solidity.
- Wallet dan transaction risk analysis.
- EVM dan Solana read-only inspector.
- Threat feed dan correlator.
- Remediation planner dan safe patcher.
- CLI dan REST API read-only.
- Automated test suite untuk Termux dan VPS.

## Instalasi Termux

```bash
pkg update && pkg upgrade
pkg install -y python python-pip git clang make pkg-config
git clone <YOUR_REPOSITORY_URL> BlueStrix_v8
cd BlueStrix_v8
chmod +x install_termux.sh
./install_termux.sh
```

## Instalasi VPS

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git build-essential
git clone <YOUR_REPOSITORY_URL> BlueStrix_v8
cd BlueStrix_v8
chmod +x install_vps.sh
./install_vps.sh
```

## Konfigurasi awal

```bash
cp config/bluestrix.example.yaml config/bluestrix.yaml
```

Edit `config/bluestrix.yaml` dan tambahkan target yang diizinkan pada bagian `scope.authorized_targets`.

## Perintah utama

```bash
source .venv/bin/activate

bluestrix --help
bluestrix policy validate
bluestrix scope check [https://example.com](https://example.com)
bluestrix scan code ./src
bluestrix asset analyze-wallet 0x0000000000000000000000000000000000000000 --chain evm
bluestrix controls
bluestrix slither ./contracts
bluestrix remediation plan --findings reports/findings.json
bluestrix safe-patch create --findings reports/findings.json --finding-id <FINDING_ID>
bluestrix audit tail --limit 20
bluestrix api --host 127.0.0.1 --port 8787
```

## Pengujian otomatis

```bash
./scripts/run_smoke_tests.sh
./scripts/run_full_test_suite.sh
```
# BlueStrix Sandbox

Sandbox lengkap untuk menjalankan BlueStrix secara aman.

Dua lapis sandbox:

1. Docker container - untuk analisis tepercaya.
2. Firecracker microVM - untuk kode tidak tepercaya, Slither, Foundry, fuzzing.

## Arsitektur

Host
├── Docker Compose
│   ├── bluestrix-api
│   ├── bluestrix-worker
│   ├── postgres
│   └── redis
└── Sandbox Layer
    ├── Docker container
    └── Firecracker microVM

## Instalasi Docker

./scripts/install_docker.sh
docker compose up -d

## Instalasi Firecracker

./scripts/install_firecracker.sh
./scripts/run_microvm_scan.sh ./target-repo

## Aturan

- Kode tidak dikenal wajib microVM.
- Docker container hanya untuk kode tepercaya.
- Network default deny.
- Filesystem default read-only.
- Tidak ada akses Docker socket host.
- Tidak ada private key di sandbox.

## Batasan

Static analysis bukan pengganti audit manusia. Temuan otomatis harus diverifikasi, terutama untuk logika ekonomi, oracle, bridge, upgradeability, dan mekanisme DeFi.
