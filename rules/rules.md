# BlueStrix Rules

File ini menjelaskan aturan operasional BlueStrix v8.0.

## Mode default

BlueStrix selalu dimulai dalam mode:

- `defensive`
- `restricted`
- read-only
- deny-by-default

Tidak ada tindakan yang mengubah state blockchain, memindahkan aset, menandatangani transaksi, atau memodifikasi file produksi tanpa persetujuan manusia.

## Scope

Semua target harus ada dalam `scope.authorized_targets`.

Target yang tidak terdaftar akan diblokir. Target yang didukung:

- Domain.
- CIDR IPv4.
- Address EVM.
- Address Solana.
- Path repository lokal.

## Action levels

| Action | Default | Keterangan |
|---|---|---|
| READ | Diizinkan | Static analysis, RPC read, report |
| WRITE | Approval | Modifikasi file atau konfigurasi |
| DEPLOY | Approval | Deploy contract |
| TRANSFER | Approval | Transfer aset |
| SIGN | Approval | Signing transaksi |
| EXECUTE | Approval | Operasi state-changing |
| REMEDIATE | Approval | Perbaikan kode otomatis |

## Auto-fix

Hanya rule berikut yang diizinkan menjadi auto-fix proposal:

- `BSX-PY-001`: hardcoded secret pada Python.
- `BSX-TS-002`: hardcoded secret pada TypeScript.

Auto-fix tetap:

1. Hanya menghasilkan diff.
2. Wajib approval pemilik kode.
3. Wajib review developer.
4. Wajib regression test.
5. Dapat di-rollback.

Rule Solidity, Rust, Move, bridge, oracle, dan upgradeability tidak boleh auto-fix otomatis.

## Protected paths

BlueStrix tidak boleh mengubah otomatis:

- `.github/workflows/`
- `.gitlab-ci.yml`
- `Dockerfile`
- `docker-compose.yml`
- `k8s/`
- `terraform/`
- `policies/`
- `config/`

## Evidence rule

Status `PASS` hanya boleh diberikan jika ada evidence.

Status berikut tidak boleh dikonversi menjadi `PASS`:

- `UNAVAILABLE`
- `INCOMPLETE`
- `NOT_TESTED`
- `BLOCKED`

## Secrets

Private key, seed phrase, mnemonic, API key, dan kredensial tidak boleh:

- Disimpan dalam repository.
- Ditulis ke log.
- Dimasukkan ke laporan.
- Dikirim sebagai argumen CLI.
- Disimpan dalam environment variable tanpa perlindungan.

## Audit

Setiap scope check, scan, inspection, approval, dan remediation harus dicatat di `data/audit.jsonl`.
