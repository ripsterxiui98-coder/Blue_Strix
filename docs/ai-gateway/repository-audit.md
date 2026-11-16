# Audit Repository — AI Gateway Foundation (Tahap 1)

Dokumen ini mencatat kondisi repository BlueStrix **sebagaimana diunggah** (`Blue_Strix-main.zip`) pada saat audit. Setiap klaim di bawah dapat diverifikasi dengan membaca file yang disebut.

## 1. Metadata repository dan keterbatasan audit

- **Bukan git repository.** Zip tidak berisi folder `.git`. Karena itu audit tidak dapat memeriksa riwayat commit, perubahan lokal yang belum di-commit, branch yang sudah ada, atau PR yang sudah terbuka.
- **Default branch tidak dapat dipastikan.** Workflow CI (`.github/workflows/*.yml`) memakai `branches: [main]`, tetapi ini hanya petunjuk, bukan bukti default branch sebenarnya. Base branch harus dikonfirmasi di GitHub sebelum PR dibuat.
- **Akses GitHub tidak tersedia** dari lingkungan ini. Branch `feat/ai-gateway-foundation` dibuat sebagai commit lokal di atas baseline zip. Push dan PR harus dilakukan pemilik repository.
- **Dependency tidak dapat dipasang** dari lingkungan ini (jaringan dimatikan). Hanya `pyyaml` yang tersedia. Lihat bagian verifikasi di `installation.md`.

## 2. Stack yang benar-benar ditemukan

| Area | Temuan | Bukti |
|---|---|---|
| Bahasa backend | Python `>=3.10`, dengan Dockerfile memakai `python:3.11-slim` | `pyproject.toml`, `infra/docker/Dockerfile.api` |
| Framework API | FastAPI + Uvicorn (extra `api`) | `pyproject.toml`, `src/bluestrix/integrations/api.py` |
| ORM dan migrasi | SQLAlchemy 2.x + Alembic | `src/bluestrix/core/database.py`, `alembic/` |
| Database | PostgreSQL 16 (compose), SQLite hanya untuk test | `docker-compose.yml`, `tests/integration/test_auth_api.py` |
| Cache / rate limit | Redis 7 (compose), opsional untuk rate limit; fallback in-memory | `src/bluestrix/core/rate_limit.py` |
| Frontend | Next.js 14.2.18, React 18, NextAuth 4, Tailwind 3, Zustand, TanStack Query | `dashboard/package.json` |
| Dependency Python | `pyyaml`, `rich`, `httpx`, `pydantic`, `email-validator` (inti) | `pyproject.toml` |
| Lint / test | Ruff (line-length 100), pytest, pytest-cov | `pyproject.toml`, `scripts/run_tests.sh` |
| CI | GitHub Actions: `sandbox-test.yml`, `security-scan.yml` | `.github/workflows/` |
| Container | Compose: postgres, redis, api, worker, scanner (scanner tanpa jaringan) | `docker-compose.yml` |

Lockfile: **tidak ada** (`poetry.lock`, `requirements.txt`, `package-lock.json`, `pnpm-lock.yaml` tidak ditemukan). Ini berarti dependency tidak dipin; lihat risiko di bagian 6.

## 3. Status file yang diminta untuk diperiksa

| File | Status |
|---|---|
| `config/ai_router.yaml` | Ada. Berisi DeepSeek (priority 1), OpenAI, Anthropic, Groq, local. |
| `src/bluestrix/ai/router.py` | Ada. `AIRouter` dengan cooldown, cache, budget harian in-memory. |
| `src/bluestrix/ai/providers.py` | Ada. Adapter OpenAI-compatible, Anthropic, dan local. Mengimpor `httpx` di level modul. |
| `src/bluestrix/integrations/deepseek.py` | Ada. Helper konfigurasi DeepSeek via InferX. |
| `tests/unit/test_ai_router.py` | Ada. 8 test. |
| `.env.example` | Ada. Berisi placeholder untuk provider AI. |

Dengan demikian, perubahan DeepSeek yang diminta pada PR sebelumnya **sudah ada** di snapshot ini. Pekerjaan tahap ini tidak menambah ulang provider tersebut.

## 4. Fitur yang sudah ada

- **Autentikasi backend**: model `User`, `AuthSession` (refresh token disimpan sebagai hash SHA-256), `PasswordResetToken`, MFA TOTP dengan recovery code hash (`src/bluestrix/core/auth.py`, `mfa.py`, `security.py`).
- **Password hashing**: argon2 jika tersedia, lalu bcrypt, lalu PBKDF2-SHA256 sebagai fallback test.
- **Rate limit login/MFA/reset** dengan Redis atau in-memory (`core/rate_limit.py`).
- **Audit trail**: `AuditEventRecord`, `core/audit.py`, `core/audit_chain.py`.
- **Scope enforcement** deny-by-default (`policy/scope.py`).
- **Remediation proposal dan approval** (`intelligence/remediation/`, tabel `RemediationProposal`, `ApprovalRecord`).
- **Migrasi**: `0001_initial_schema`, `0002_users_sessions_mfa`.
- **Dashboard**: halaman login, approvals, audit, findings, marketplace, settings; NextAuth dengan provider credentials.

## 5. Kekurangan untuk mendukung BYOK multi-tenant

1. **Tidak ada konsep workspace atau tenant.** Pencarian `workspace|tenant|org_id` di `src/`, `dashboard/src/`, dan `alembic/` menghasilkan nol hasil. Semua tabel bersifat global.
2. **Tidak ada tabel penyimpanan credential provider pelanggan.** Provider key hanya datang dari environment variable.
3. **Auth router tidak di-mount.** `src/bluestrix/integrations/auth_routes.py` mendefinisikan `/auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/session`, MFA, dan reset password, tetapi `create_app()` di `api.py` tidak memanggil `include_router`. Akibatnya:
   - `tests/integration/test_auth_api.py` memanggil `/auth/register` dan `/auth/login` pada app dari `create_app`. Berdasarkan pembacaan kode, test ini kemungkinan gagal. Belum dapat dijalankan di sini karena FastAPI tidak tersedia.
   - Dashboard (`dashboard/src/app/api/auth/login/route.ts`, `lib/auth.ts`) memanggil `${API_URL}/auth/login`, yang tidak dilayani API saat ini.
4. **Otorisasi endpoint write hanya berupa header.** `_require_operator` di `api.py` hanya memeriksa keberadaan header `X-BlueStrix-Operator`. Nilai header dapat dipalsukan oleh siapa pun. Endpoint PATCH findings, POST remediation proposals, dan POST approvals dapat dipanggil tanpa login.
5. **Endpoint read tidak diautentikasi.** `GET /findings`, `GET /findings/{id}`, `GET /audit`, `GET /remediation/proposals` tidak memiliki dependency auth.
6. **Dashboard tidak mengirim token.** `dashboard/src/lib/api.ts` memanggil API tanpa `Authorization`. Token akses NextAuth tidak diteruskan.
7. **Tidak ada pembatasan kepemilikan data.** Tidak ada kolom `owner_id` atau `workspace_id` pada `ScanRun`, `FindingRecord`, `RemediationProposal`, atau `ApprovalRecord`.
8. **Kebijakan fallback tidak disetujui pelanggan.** `config/ai_router.yaml` mengaktifkan fallback otomatis ke OpenAI, Anthropic, dan Groq dengan key platform. Di model BYOK, fallback ke provider yang dibayar platform harus disetujui pelanggan.
9. **Budget dan quota tidak durabel.** `RouterState` disimpan di memori proses. Saat restart, counter hilang, dan budget tidak dibagi antar-replica.
10. **`max_retries_per_provider` tidak dipakai.** Nilai ini ada di YAML, tetapi `AIRouter` tidak membacanya.
11. **`DATABASE_URL` tidak ada di `.env.example`**, padahal `docker-compose.yml` mengisinya dari `${DATABASE_URL}` untuk api dan worker. Sudah diperbaiki pada tahap ini dengan placeholder.

## 6. Risiko keamanan

| ID | Risiko | Tingkat | Status pada tahap ini |
|---|---|---|---|
| R1 | Endpoint write dapat diakses dengan header yang dipalsukan (`X-BlueStrix-Operator`). | Tinggi | Tidak diubah. Dicatat sebagai blocker auth/workspace. |
| R2 | Endpoint read findings dan audit tanpa autentikasi. | Tinggi | Tidak diubah. |
| R3 | Auth router tidak di-mount; `register` bootstrap admin untuk user pertama (menurut komentar test). Mount tanpa kajian dapat membuka akun admin ke publik. | Tinggi jika di-mount tanpa kajian | Sengaja tidak di-mount. |
| R4 | `get_jwt_secret()` membuat secret acak sementara jika `BLUESTRIX_JWT_SECRET` tidak ada. Sesi putus setiap restart, dan `BLUESTRIX_DEV_JWT_SECRET` dapat menjadi secret produksi secara tidak sengaja. | Sedang | Ditangani oleh validasi production di `settings.py`. |
| R5 | MFA secret dienkripsi dengan envelope buatan sendiri (XOR + HMAC), kuncinya diturunkan dari JWT secret secara default. Ini bukan AEAD yang teruji. | Sedang | Tidak diubah. Tidak boleh dipakai ulang untuk credential provider. |
| R6 | `DEFAULT_DATABASE_URL` berisi password `change-me`. | Rendah (dev) | Ditolak di production oleh `settings.py`. |
| R7 | Dependency tidak dipin (tidak ada lockfile). | Sedang | Tidak diubah. Perlu lockfile di tahap berikutnya. |
| R8 | Kode kustom base URL belum punya mitigasi SSRF. | Sedang | Ditangani: allowlist https dan host tetap di `settings.validate_base_url`. |
| R9 | Redaction hanya berbasis pola di `secret_redaction.py`, tidak mencakup `sk-` atau Bearer token. | Sedang | Diperluas di `gateway/redaction.py`. Tidak menggantikan kebijakan "jangan log secret". |
| R10 | Compose tidak punya service dashboard dan healthcheck untuk api. | Rendah | Tidak diubah. |
| R11 | Dockerfile.api memakai user non-root `bluestrix` (uid 10001). Container worker/scanner tidak diverifikasi di sini. | Info | Tidak diubah. |

Hal yang sudah benar: port postgres dan redis tidak dipublish (hanya network internal); api dipublish ke `127.0.0.1`; scanner memakai `network_mode: none`, `read_only`, `cap_drop: ALL`, dan `no-new-privileges`; tidak ada `docker.sock` atau `privileged: true` di compose.

## 7. Dependency baru

**Tahap ini tidak menambah dependency Python atau JavaScript.** Modul gateway hanya memakai stdlib, `pyyaml`, dan `httpx` yang sudah menjadi dependency inti.

Yang direncanakan untuk tahap berikutnya (belum dipasang, perlu verifikasi versi dan lisensi):

- **Library AEAD** (misalnya `cryptography`) untuk envelope encryption credential BYOK. Alasan: envelope buatan sendiri di `security.py` tidak boleh dipakai untuk credential. Lisensi dan versi harus dicek sebelum dipasang.
- **Lockfile** (pip-tools atau uv) agar dependency terpin. Alasan: R7.

## 8. Evaluasi LiteLLM

Evaluasi ini **tidak dapat diverifikasi terhadap versi terkini** karena tidak ada akses jaringan. Yang dapat dinyatakan dengan jujur:

- LiteLLM menyediakan abstraksi multi-provider, routing, dan (pada mode proxy) fitur seperti virtual key, budget, dan pencatatan spend. Namun, ketersediaan dan batasan fitur-fitur tersebut berbeda per versi dan per lisensi. **Tidak boleh diasumsikan gratis atau otomatis aktif.**
- LiteLLM membawa lapisan routing dan fallback sendiri. Menggunakannya bersama `AIRouter` berisiko menghasilkan dua lapis fallback yang saling bertentangan.
- **Keputusan tahap ini:** LiteLLM **tidak diadopsi**. Router BlueStrix tetap menjadi satu-satunya lapis fallback. Evaluasi ulang harus dibuat sebagai ADR terpisah dengan versi terpin, daftar fitur dari dokumentasi resmi, dan pemeriksaan lisensi.

## 9. Rencana implementasi bertahap

1. **Tahap 1 (PR ini): fondasi.** Validasi environment, redaction, liveness/readiness, adapter berbatas, dokumentasi, test. Tidak ada endpoint credential, tidak ada perubahan auth.
2. **Tahap 2: autentikasi dan workspace.** Mount auth router setelah kajian R3. Ganti `X-BlueStrix-Operator` dengan identitas dari JWT. Tambah tabel `workspaces` dan `workspace_members`, lalu kolom `workspace_id` pada data. Tambah migrasi dengan rollback.
3. **Tahap 3: BYOK vault.** Tabel `provider_connections`, envelope encryption dengan AEAD, endpoint sesuai `byok-api-contract.md`, audit event tanpa credential.
4. **Tahap 4: routing dan fallback yang disetujui pelanggan, quota durabel, dan pelacakan penggunaan.**
5. **Tahap 5: langganan dan pembayaran.** Belum dirancang. Tidak ada kredit atau aktivasi paket pada tahap manapun sebelum ada integrasi pembayaran yang teruji.

Usulan scope PR berikutnya: **autentikasi dan workspace** (tahap 2), karena semua tahap BYOK bergantung pada identitas dan batas workspace yang tepercaya.
