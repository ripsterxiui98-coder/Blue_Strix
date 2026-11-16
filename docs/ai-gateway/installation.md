# Panduan Pemasangan — AI Gateway Foundation (Tahap 1)

Panduan ini hanya mencakup **pengembangan lokal**. Bagian 14 menjelaskan apa yang harus ada sebelum production.

Yang **tidak** tersedia pada tahap ini: halaman dashboard untuk provider, endpoint BYOK, dan fallback yang disetujui pelanggan. Jangan mencari fitur tersebut di dashboard.

---

## 1. Prasyarat

| Komponen | Versi | Catatan |
|---|---|---|
| Python | 3.10 atau lebih baru (Docker memakai 3.11) | Sesuai `requires-python` di `pyproject.toml`. |
| pip dan venv | Bawaan Python | |
| Git | Versi apa pun yang mendukung `git checkout` | |
| Docker dan Docker Compose v2 | Untuk PostgreSQL dan Redis | Opsional jika menjalankan tes saja. |
| Node.js | 18 atau lebih baru | Hanya jika menjalankan dashboard. Tidak dibutuhkan pada tahap ini. |

## 2. Clone repository dan checkout branch

```bash
git clone <URL_REPOSITORY> BlueStrix
cd BlueStrix
git fetch origin
git checkout feat/ai-gateway-foundation
```

Pastikan base branch PR adalah default branch repository. Tahap ini tidak mengasumsikan `main`.

## 3. Instalasi dependency Python

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip wheel
pip install -e ".[dev,api,database,auth]"
```

Catatan:
- Tidak ada lockfile di repository. Versi yang terpasang bisa berbeda antar mesin. Ini diketahui dan dicatat sebagai risiko R7 di `repository-audit.md`.
- `httpx` adalah dependency inti. Modul gateway dan test membutuhkannya saat import `bluestrix.ai.providers`.

## 4. Membuat konfigurasi lokal

```bash
cp .env.example .env
cp config/bluestrix.example.yaml config/bluestrix.yaml
```

Edit `.env` dan pastikan nilai berikut untuk pengembangan lokal:

```bash
BLUESTRIX_ENV=development
```

Tanpa baris ini, `/health/ready` mengembalikan `503` karena nilai yang tidak diset diperlakukan sebagai production (fail secure).

Placeholder `change-me` di `.env` hanya boleh dipakai di development. Jangan menyalin `.env` ke server production.

API key provider (`DEEPSEEK_API_KEY`, `OPENAI_API_KEY`, dan lainnya) tidak wajib untuk menjalankan API atau test. Jika kosong, adapter mengembalikan error `missing_api_key` tanpa melakukan request. Jangan mengisi key asli di `.env` yang ikut ter-commit. File `.env` sudah ada di `.gitignore`.

Konfigurasi tidak boleh diisi dengan secret asli di `config/*.yaml`. Key provider hanya dibaca dari environment.

## 5. Menjalankan layanan pendukung (opsional)

```bash
docker compose up -d postgres redis
docker compose ps
```

Port PostgreSQL dan Redis tidak dipublish ke host. Hostname `postgres` di `DATABASE_URL` hanya dapat di-resolve dari dalam network compose.

Akibatnya, pada tahap ini API yang berjalan langsung di host tidak dapat terhubung ke PostgreSQL di compose. Ini sengaja: database tidak boleh terbuka ke host tanpa keputusan eksplisit. Untuk pengembangan database yang membutuhkan akses dari host, tambahkan port publish `127.0.0.1:5432:5432` pada service postgres secara sadar, dan ubah host di `DATABASE_URL` menjadi `localhost`. Perubahan ini di luar cakupan tahap 1.

## 6. Migrasi database

```bash
set -a; source .env; set +a
alembic upgrade head
```

- Membutuhkan PostgreSQL yang aktif dan `DATABASE_URL` yang valid.
- Revision saat ini: `0001_initial`, lalu `0002_auth`.
- Migrasi pada tahap ini **tidak menambahkan tabel baru**.
- Rollback satu langkah: `alembic downgrade -1`. Lakukan hanya pada database development.

## 7. Menjalankan API

```bash
set -a; source .env; set +a
bluestrix api --host 127.0.0.1 --port 8787
```

API hanya mendengarkan di loopback. Jangan mengubah `--host` ke `0.0.0.0` di luar container.

## 8. Memeriksa health endpoint

Di terminal lain:

```bash
curl -s http://127.0.0.1:8787/health
curl -s http://127.0.0.1:8787/health/live
curl -s -i http://127.0.0.1:8787/health/ready
```

Hasil yang diharapkan dengan `BLUESTRIX_ENV=development`:

- `/health`: `{"status":"ok", ...}` (endpoint lama, tidak berubah).
- `/health/live`: `{"status":"ok"}`.
- `/health/ready`: `HTTP/1.1 200 OK` dengan `"status":"ready"`.

Jika `/health/ready` mengembalikan `503`, periksa log server. Pesan masalah konfigurasi hanya muncul di log, tidak di respons.

`/health/live` dan `/health/ready` tidak memanggil provider AI dan tidak membuat request berbayar.

## 9. Menjalankan test

Test gateway (tidak membuka koneksi jaringan, memakai transport palsu):

```bash
pytest tests/unit/test_gateway_foundation.py -q
```

Atau tanpa pytest, dengan `unittest` bawaan Python:

```bash
PYTHONPATH=src python -m unittest tests/unit/test_gateway_foundation.py -v
```

Test router yang sudah ada:

```bash
pytest tests/unit/test_ai_router.py -q
```

Suite lengkap seperti biasa:

```bash
./scripts/run_tests.sh
```

Catatan: `scripts/run_tests.sh` menjalankan `tests/unit`, `tests/security`, dan `tests/regression`. Test integrasi (`tests/integration`) membutuhkan FastAPI dan SQLite dan dijalankan terpisah dengan `pytest tests/integration`. Lihat catatan `test_auth_api.py` di `repository-audit.md` bagian 5.

Lint:

```bash
ruff check src/bluestrix/gateway src/bluestrix/integrations/api.py tests/unit/test_gateway_foundation.py
```

## 10. Menghentikan aplikasi

- API: tekan `Ctrl+C` di terminal tempat `bluestrix api` berjalan.
- Layanan compose: `docker compose stop postgres redis`. Gunakan `docker compose down` hanya jika ingin menghapus container. Volume `postgres_data` tetap ada kecuali dihapus dengan `-v`.
- Nonaktifkan virtual environment: `deactivate`.

## 11. Pemecahan masalah

| Gejala | Penyebab yang mungkin | Tindakan |
|---|---|---|
| `/health/ready` mengembalikan `503` | `BLUESTRIX_ENV` tidak diset, atau placeholder dipakai di production | Set `BLUESTRIX_ENV=development` untuk lokal. Periksa log server untuk daftar masalah. |
| `ModuleNotFoundError: httpx` | Dependency belum terpasang | Jalankan `pip install -e ".[dev,api,database,auth]"` di venv aktif. |
| `BlueStrix error: Install API deps: pip install 'bluestrix[api]'` | Extra `api` belum terpasang | Pasang dengan `pip install -e ".[api]"`. |
| `ConfigurationError: Configuration file not found: config/bluestrix.yaml` | `config/bluestrix.yaml` belum dibuat | Jalankan langkah 4. |
| `docker compose` gagal dengan `DATABASE_URL` kosong | `.env` belum dibuat dari `.env.example` | Jalankan `cp .env.example .env`. |
| Test gagal karena jaringan | Test seharusnya tidak membuka jaringan. Jika ini terjadi, ada perubahan yang melanggar aturan tes | Hentikan dan periksa `tests/unit/test_gateway_foundation.py`. |
| Error `missing_api_key` dari adapter | Key provider belum diisi di environment | Ini perilaku yang benar jika key memang belum ada. Tidak ada request yang dikirim. |

## 12. Batasan development

- Tidak ada autentikasi yang diterapkan pada endpoint gateway baru. Readiness dan liveness memang tidak memerlukan autentikasi.
- Endpoint write yang sudah ada (`X-BlueStrix-Operator`) dapat dipalsukan. Jangan mengekspos API ke jaringan yang tidak tepercaya dalam kondisi apa pun.
- Auth router (`/auth/*`) belum di-mount di API. Pendaftaran dan login melalui API tidak tersedia pada tahap ini.
- Budget, cache, dan cooldown router hanya ada di memori proses.
- Tidak ada koneksi dashboard ke gateway pada tahap ini.

## 13. Yang sudah diverifikasi dan yang belum

Lihat bagian "Verifikasi" di laporan akhir. Ringkasan singkat:

- **Sudah dijalankan**: test unit gateway dan test router yang sudah ada, dijalankan dengan `unittest` dan stub import `httpx` yang hanya berada di luar repository (lihat laporan).
- **Belum dijalankan**: `pip install`, `pytest`, `ruff`, `alembic`, `docker compose`, `bluestrix api`, dan test integrasi FastAPI. Alasan: jaringan dimatikan dan FastAPI, SQLAlchemy, serta pytest tidak tersedia di lingkungan audit.

## 14. Sebelum production

Jangan menganggap tahap ini siap production. Sebelum deploy, diperlukan minimal:

1. Mengisi `BLUESTRIX_ENV=production`, `BLUESTRIX_JWT_SECRET`, dan `BLUESTRIX_MFA_KEY` dengan secret acak minimal 32 karakter yang berbeda satu sama lain, dari secret store deployment. Contoh pembuatan: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`.
2. Mengisi `DATABASE_URL` dengan password non-placeholder.
3. Menghapus `BLUESTRIX_DEV_JWT_SECRET` dari environment.
4. Menyelesaikan blocker autentikasi dan otorisasi (R1, R2, R3 di `repository-audit.md`).
5. Menjalankan `/health/ready` dan memastikan hasilnya `200`.
6. Memastikan secret tidak pernah masuk ke image Docker, repository, atau log.

Validasi production di `settings.py` hanya memeriksa konfigurasi. Validasi ini bukan pengganti audit keamanan.
