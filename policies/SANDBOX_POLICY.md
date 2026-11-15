# Sandbox Policy

## Prinsip

1. Kode tidak dikenal wajib microVM.
2. Docker container hanya untuk kode tepercaya.
3. Network default deny.
4. Filesystem default read-only.
5. Tidak ada akses Docker socket host.
6. Tidak ada private key di sandbox.
7. Timeout wajib.
8. Memory dan CPU wajib dibatasi.
9. Patch wajib approval owner.
10. Semua aktivitas wajib audit.

## Level sandbox

| Level | Teknologi | Kegunaan |
|---|---|---|
| 1 | Process isolation | Scan file teks |
| 2 | Docker container | Analisis tepercaya |
| 3 | Firecracker microVM | Kode tidak tepercaya |

## Larangan

- Jangan mount `/` ke sandbox.
- Jangan mount Docker socket host.
- Jangan beri akses root.
- Jangan beri network unrestricted.
- Jangan menyimpan secret di sandbox.
- Jangan menjalankan kode pihak ketiga di host langsung.
