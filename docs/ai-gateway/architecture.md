# Arsitektur AI Gateway BlueStrix

Status dokumen: **keputusan tahap 1**. Bagian yang berstatus *belum diimplementasikan* ditandai jelas.

## 1. Tiga jenis identitas yang tidak boleh dicampur

| Identitas | Siapa yang memiliki | Disimpan di mana | Dikembalikan ke klien? | Status |
|---|---|---|---|---|
| **API key provider** (OpenAI, DeepSeek/InferX, Anthropic, Groq) | Pelanggan (BYOK) atau platform | Tahap 1: environment variable. Tahap 3: vault terenkripsi | **Tidak pernah**, bahkan setelah disimpan | Tahap 1: env only. Vault belum ada. |
| **Virtual key gateway** (kunci yang dikeluarkan BlueStrix untuk aplikasi pelanggan memanggil gateway) | BlueStrix untuk workspace tertentu | Hash di database, plaintext hanya ditampilkan sekali saat dibuat | Hanya sekali saat dibuat | **Belum diimplementasikan.** Dibahas di tahap 3 atau 4. |
| **Sesi login pengguna** (JWT access 15 menit, refresh token) | Pengguna dashboard | Refresh token disimpan sebagai hash SHA-256 (`AuthSession`). Access token dalam memori. | Access token ke klien, refresh token via cookie | **Sudah ada.** Tidak diubah pada tahap ini. |

Aturan turunan:

- Sesi pengguna tidak boleh dipakai sebagai kredensial provider, dan sebaliknya.
- Virtual key tidak boleh menjadi API key provider dan tidak boleh menggantikan sesi.
- Tidak ada identitas yang diterima dari body request untuk menentukan pemilik workspace. Pemilik ditentukan dari identitas terautentikasi.

## 2. Batas tanggung jawab

### Dashboard (Next.js)

Tanggung jawab:
- Form input provider, input API key (tipe `password`, tidak disimpan ke `localStorage`), pemilihan model, dan tampilan status koneksi.
- Menampilkan status dari backend tanpa pernah menampilkan credential.

Batasan:
- Tidak memegang credential provider setelah dikirim.
- Tidak melakukan panggilan langsung ke provider AI.
- **Saat ini belum mengirim access token ke API** (`dashboard/src/lib/api.ts`). Perbaikan dijadwalkan bersama tahap autentikasi.

### Backend (FastAPI)

Tanggung jawab:
- Autentikasi dan otorisasi setiap operasi.
- Isolasi workspace: setiap query data dibatasi oleh `workspace_id` dari identitas terautentikasi.
- Penyimpanan credential terenkripsi (tahap 3).
- Persetujuan routing dan fallback oleh pelanggan (tahap 4).
- Kebijakan penggunaan: batas budget dan quota per workspace (tahap 4).
- Audit event untuk setiap aksi, tanpa menyertakan credential.

Yang sudah ada pada tahap 1:
- `bluestrix.gateway.settings`: validasi environment, fail secure, allowlist base URL.
- `bluestrix.gateway.health`: liveness dan readiness.
- `bluestrix.gateway.redaction`: redaction untuk log dan error.

### Gateway (adapter ke provider)

Tanggung jawab:
- Akses ke model provider melalui adapter OpenAI-compatible.
- Timeout per request.
- Retry terbatas, **hanya** untuk kegagalan sementara.
- Pencatatan penggunaan (token dan estimasi biaya dari respons).

Batasan:
- Gateway tidak menentukan urutan fallback lintas-provider. Keputusan itu ada di `AIRouter` (lihat bagian 3).
- Gateway tidak mencatat isi prompt atau respons secara default.

### Pembayaran

**Belum diimplementasikan, dan tidak ada tiruan.**
- Tidak ada penambahan saldo, aktivasi paket, atau kredit.
- Budget `budget_usd_daily` pada router adalah batas teknis internal, bukan fitur penagihan.

## 3. Routing dan fallback: satu lapis saja

Sistem sekarang memiliki dua tempat yang berpotensi melakukan fallback. Tahap ini menetapkan satu aturan:

- **`AIRouter` (`src/bluestrix/ai/router.py`)** adalah satu-satunya lapis yang memilih provider dan berpindah ke provider berikutnya.
- **`GatewayAdapter` (`src/bluestrix/gateway/adapter.py`)** menangani satu panggilan ke satu provider: timeout, retry sementara, dan error yang aman. Ia **tidak** berpindah ke provider lain.

Dengan aturan ini, retry di adapter (maksimal 3 kali tambahan, default 1) dan fallback di router tidak saling menggandakan panggilan secara tak terbatas. Total percobaan per request = jumlah provider yang dicoba × (retry adapter + 1).

Catatan: `GatewayAdapter` **belum dipasang ke `AIRouter`** pada tahap ini. Router masih memakai `providers.py` yang ada. Pemasangan dilakukan pada tahap 4 bersama persetujuan fallback pelanggan.

## 4. Keputusan LiteLLM

**Tidak diadopsi pada tahap ini.** Alasan:

1. Ketersediaan dan batas fitur (virtual key, budget, spend tracking) berbeda antar versi dan mode (library vs proxy). Belum diverifikasi terhadap versi terpin karena tidak ada akses jaringan.
2. Fitur-fitur tersebut tidak boleh diasumsikan gratis atau otomatis aktif. Sebagian fitur lanjutan membutuhkan konfigurasi atau lisensi tertentu yang harus diperiksa langsung di dokumentasi versi yang dipilih.
3. LiteLLM membawa lapisan routing dan fallback sendiri. Memakainya berdampingan dengan `AIRouter` akan menciptakan dua lapis fallback yang saling bertentangan.
4. Menambahkan proxy LiteLLM berarti menambah service, database, dan permukaan keamanan baru, yang belum dibutuhkan oleh fondasi ini.

Kondisi untuk mengevaluasi ulang: ADR baru dengan versi terpin, daftar fitur dari dokumentasi resmi, pemeriksaan lisensi, dan bukti bahwa tidak ada lapis fallback ganda.

## 5. Timeout, retry, dan batas

| Parameter | Nilai default | Batas | Sumber |
|---|---|---|---|
| Timeout per request | 30 detik | 1–120 detik | `BLUESTRIX_AI_TIMEOUT_SECONDS` |
| Retry per provider | 1 | 0–3 | `BLUESTRIX_AI_MAX_RETRIES` |
| Status yang di-retry | 429, 500, 502, 503, 504, timeout, error koneksi | — | `adapter.TRANSIENT_STATUS_CODES` |
| Status yang TIDAK di-retry | 400, 401, 403, 404, respons tidak valid | — | — |
| Backoff | 0,5 detik × nomor percobaan | — | `adapter.BACKOFF_SECONDS` |
| Redirect | Dimatikan (`follow_redirects=False`) | — | `HttpxTransport` |

Catatan: `budget_usd_daily`, `cache_ttl_seconds`, dan `cooldown_seconds` di YAML tetap berlaku seperti sebelumnya dan tidak diubah.

## 6. Keamanan base URL (mitigasi SSRF)

- Hanya `https`.
- Tanpa kredensial di URL (`user:pass@`).
- Hanya port default 443.
- Host harus ada di allowlist tetap: `model.inferx.net`, `api.openai.com`, `api.anthropic.com`, `api.groq.com`.
- Diperiksa saat konfigurasi divalidasi **dan** saat adapter dibuat.
- Tidak ada base URL yang diterima dari input pengguna. Kode custom base URL untuk pelanggan dinonaktifkan sampai ada persetujuan dan daftar host per workspace.

## 7. Health endpoint

| Endpoint | Yang diperiksa | Yang TIDAK dilakukan |
|---|---|---|
| `GET /health` | Endpoint lama, tidak diubah. | — |
| `GET /health/live` | Proses berjalan. | Tidak membaca env, tidak memanggil provider. |
| `GET /health/ready` | Konfigurasi environment valid. Respons hanya berisi status dan jumlah provider yang terkonfigurasi. | Tidak memanggil provider, tidak membuat request berbayar, tidak mengembalikan detail masalah konfigurasi (karena endpoint ini tidak diautentikasi). |

Readiness mengembalikan `503` jika konfigurasi production tidak valid. Detail masalah tersedia di log server melalui `assess_environment()`.

**Belum diperiksa oleh readiness:** koneksi database. Ini ditambahkan bersama migrasi pada tahap berikutnya, karena membutuhkan database yang aktif dan pemeriksaan ini tidak boleh membuat query yang mahal.

## 8. Pemisahan lingkungan

| Environment | `BLUESTRIX_ENV` | Aturan |
|---|---|---|
| Development | `development` | Placeholder diizinkan dengan peringatan. |
| Test | `test` | Sama dengan development. Tidak boleh memanggil provider berbayar di CI. |
| Production | `production` (atau tidak diset) | Secret wajib kuat (32+ karakter) dan berbeda satu sama lain. `DATABASE_URL` wajib dan tanpa placeholder. `BLUESTRIX_DEV_JWT_SECRET` dilarang. |

Keputusan fail secure: nilai yang tidak diset atau tidak dikenal diperlakukan sebagai production. Konsekuensinya, pengembang harus secara eksplisit menyetel `BLUESTRIX_ENV=development` untuk pengembangan lokal.

## 9. Logging dan redaction

- `RedactingFilter` menghapus nilai secret yang terdaftar, pola Bearer token, pola `sk-…`, header sensitif, dan traceback yang memuat secret.
- Filter **harus dipasang secara eksplisit** pada handler oleh pemanggil. Tahap ini belum mengkonfigurasi logging global aplikasi.
- Header `Authorization` tidak pernah dicatat. `repr()` dari `GatewayAdapter` tidak menampilkan key.
- Error provider dikembalikan sebagai kode tetap (`timeout`, `http_401`, `missing_api_key`, `unexpected_response`) atau teks yang sudah di-redact.

## 10. Yang belum diimplementasikan (eksplisit)

- Endpoint BYOK (lihat `byok-api-contract.md`).
- Tabel workspace, membership, dan provider connection. Tidak ada migrasi baru pada tahap 1.
- Penyimpanan credential terenkripsi.
- Virtual key gateway.
- Routing dan fallback yang disetujui pelanggan.
- Quota dan budget yang durabel per workspace.
- Pelacakan penggunaan per workspace.
- Dashboard halaman pengelolaan provider.
- Pembayaran dan langganan.
- Integrasi GitHub.
