# Kontrak API BYOK (provider connections)

**Status: spesifikasi. Belum diimplementasikan.** Tidak ada endpoint berikut yang ada di kode pada tahap 1. Dokumen ini adalah kontrak yang harus dipenuhi implementasi tahap 3.

Semua path berada di bawah prefix `/v1`. Semua operasi memerlukan sesi terautentikasi.

## 1. Prinsip yang berlaku untuk semua endpoint

1. **Pemilik workspace ditentukan dari identitas terautentikasi**, bukan dari body request atau query string. Path `{workspace_id}` hanya dipakai sebagai referensi, lalu diverifikasi terhadap membership pengguna.
2. **Setiap operasi memeriksa otorisasi** pada dua level: membership workspace dan role yang diperlukan.
3. **Credential tidak pernah dikembalikan** setelah disimpan. Tidak ada `api_key`, tidak ada potongan key (misalnya `last4`), tidak ada fingerprint yang dapat dibalik.
4. **Credential tidak disimpan di `localStorage`** oleh dashboard dan tidak dicatat di log.
5. **Tidak ada custom base URL** kecuali sudah lolos mitigasi SSRF pada `validate_base_url` dan disetujui secara eksplisit. Pada kontrak ini, `base_url` berasal dari preset provider, bukan dari klien.
6. **Test koneksi berbayar** hanya dijalankan dengan persetujuan eksplisit dari pengguna.
7. **Audit event** dicatat untuk setiap operasi. Event tidak memuat credential, hanya ID, aksi, aktor, dan hasil.

## 2. Role yang diperlukan

Role yang ada saat ini (`admin`, `security_analyst`, `protocol_owner`, `incident_responder`) adalah role global, bukan role per workspace. **Keputusan terbuka:** pemetaan role workspace (misalnya `owner`, `admin`, `member`, `viewer`) harus ditetapkan pada tahap 2 sebelum kontrak ini diimplementasikan.

Sampai keputusan itu dibuat, aturan minimum:

| Operasi | Role minimum |
|---|---|
| Daftar koneksi (tanpa credential) | member |
| Buat, uji, perbarui model | admin |
| Rotasi credential, hapus | owner |

## 3. Model data koneksi

Field yang boleh dikembalikan ke klien:

```json
{
  "id": "uuid",
  "workspace_id": "uuid",
  "provider": "deepseek | openai | anthropic | groq",
  "label": "string, maks 80 karakter",
  "model": "string, harus ada di daftar model yang diizinkan untuk provider",
  "status": "untested | ok | failed | revoked",
  "credential_stored": true,
  "last_tested_at": "ISO-8601 atau null",
  "last_error_code": "kode tetap, misalnya timeout | http_401 | unexpected_response | null",
  "created_at": "ISO-8601",
  "updated_at": "ISO-8601"
}
```

Field yang **tidak boleh** muncul di respons mana pun: `api_key`, `api_key_encrypted`, `dek`, potongan key, header `Authorization`, atau isi respons provider mentah.

## 4. Endpoint

### 4.1 Buat koneksi

`POST /v1/workspaces/{workspace_id}/provider-connections`

Body:

```json
{
  "provider": "deepseek",
  "label": "Produksi DeepSeek",
  "model": "deepseek-v4.1-flash-1017",
  "api_key": "write-only, tidak pernah dikembalikan"
}
```

- `201`: mengembalikan model koneksi (bagian 3). Status awal `untested`.
- `422`: provider tidak dikenal, model tidak diizinkan, atau key kosong / placeholder.
- `409`: label sudah dipakai dalam workspace yang sama.
- Field `base_url` tidak diterima. Jika dikirim, ditolak dengan `422`.

### 4.2 Daftar koneksi

`GET /v1/workspaces/{workspace_id}/provider-connections`

- `200`: daftar koneksi tanpa credential. Hanya workspace milik pengguna.

### 4.3 Uji koneksi

`POST /v1/workspaces/{workspace_id}/provider-connections/{connection_id}/test`

Body:

```json
{ "confirm_paid_request": true }
```

- Tanpa `confirm_paid_request: true`, server **menolak** dengan `412` dan tidak melakukan panggilan apa pun ke provider.
- Dengan persetujuan, server melakukan satu request kecil dengan timeout dari konfigurasi. Hasil: `status` menjadi `ok` atau `failed`, dan `last_error_code` diisi dengan kode tetap.
- Respons tidak memuat isi respons provider mentah.
- Tidak ada retry pada endpoint uji. Pengguna dapat mengulang secara manual.

### 4.4 Perbarui model

`PATCH /v1/workspaces/{workspace_id}/provider-connections/{connection_id}`

Body:

```json
{ "model": "model-yang-diizinkan" }
```

- Hanya field `model` dan `label` yang dapat diubah. Field lain diabaikan dengan `422`.
- Perubahan model mengubah status menjadi `untested`.

### 4.5 Rotasi credential

`POST /v1/workspaces/{workspace_id}/provider-connections/{connection_id}/rotate`

Body:

```json
{ "api_key": "key baru, write-only" }
```

- Key lama dinonaktifkan secara atomik bersama penyimpanan key baru. Jika salah satu gagal, keduanya tidak berubah.
- Status menjadi `untested`.
- Respons tidak memuat key baru maupun key lama.

### 4.6 Hapus koneksi

`DELETE /v1/workspaces/{workspace_id}/provider-connections/{connection_id}`

- Credential dihapus dari penyimpanan. Baris koneksi ditandai `revoked` (soft delete) untuk audit.
- Respons `204`.

## 5. Kode error

| Kode | Arti | Catatan |
|---|---|---|
| `401` | Tidak terautentikasi | |
| `403` | Terautentikasi tetapi role tidak cukup | |
| `404` | Koneksi atau workspace tidak ditemukan **atau bukan milik pengguna** | Sengaja sama, agar keberadaan resource lain tidak dapat ditebak. |
| `409` | Konflik (label duplikat) | |
| `412` | Persetujuan paid request belum diberikan | |
| `422` | Validasi gagal | Pesan tidak memuat nilai credential. |
| `429` | Rate limit | Memakai `rate_limit.py` yang ada. |
| `502` | Provider gagal saat uji | Tanpa detail provider mentah. |

## 6. Penyimpanan credential (persyaratan tahap 3)

- Envelope encryption dengan AEAD yang teruji. **Tidak boleh memakai envelope buatan sendiri** seperti `encrypt_mfa_secret` di `security.py`.
- Key encryption key (KEK) berasal dari environment atau KMS. Tidak ada default. Production menolak start jika KEK tidak ada atau placeholder (dijamin oleh `assess_environment`, ditambahkan pada tahap 3).
- Setiap credential memiliki data encryption key (DEK) sendiri.
- Nilai credential tidak pernah masuk ke ORM object yang di-serialize ke JSON.
- Library AEAD perlu dipilih, diperiksa lisensinya, dan dipin versinya sebelum tahap 3.

## 7. Migrasi dan rollback (persyaratan tahap 3)

- Tabel `provider_connections` dibuat lewat Alembic revision baru.
- `downgrade()` harus menghapus tabel dan indeks dengan urutan terbalik, dan harus diuji pada database kosong dan database berisi data.
- Data credential yang sudah terenkripsi tidak dapat dipulihkan setelah downgrade. Operator harus diberi tahu dan diminta membuat backup terenkripsi terlebih dahulu.

## 8. Test yang harus ada pada tahap 3

- Pengguna dari workspace lain menerima `404`, bukan `403`.
- Body dengan `workspace_id` berbeda dari path tidak mengubah pemilik.
- Respons `GET` tidak memuat string key yang diuji (pemeriksaan pada seluruh body respons).
- Log tidak memuat key (pemeriksaan dengan `RedactingFilter` dan assert pada output).
- `base_url` dari klien ditolak.
- Uji koneksi tanpa `confirm_paid_request` tidak memanggil transport (fake transport dengan hitungan panggilan = 0).
- Rotasi gagal di tengah tidak meninggalkan key lama tidak aktif tanpa key baru.
