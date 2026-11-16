# BlueStrix Scrutiny Checklist

Gunakan checklist ini sebelum laporan atau patch dinyatakan siap.

## Scope

- [ ] Target berada dalam `scope.authorized_targets`.
- [ ] Tidak ada target di luar otorisasi.
- [ ] Scope check tercatat di audit log.

## Evidence

- [ ] Setiap `PASS` memiliki evidence.
- [ ] Setiap `FAIL` memiliki lokasi dan bukti.
- [ ] Tidak ada status yang dipalsukan.
- [ ] Hash file disimpan untuk reproducibility.

## Code analysis

- [ ] Rule ID tercatat.
- [ ] Severity sesuai.
- [ ] Confidence masuk akal.
- [ ] Tidak ada false positive yang dipaksakan menjadi critical.
- [ ] Temuan telah diverifikasi dalam konteks bisnis.

## Smart contract

- [ ] Reentrancy diperiksa.
- [ ] Access control diperiksa.
- [ ] Upgradeability diperiksa.
- [ ] Oracle diperiksa.
- [ ] Bridge diperiksa.
- [ ] Token approval diperiksa.
- [ ] Front-running diperiksa.
- [ ] Gas DoS diperiksa.

## Remediation

- [ ] Patch hanya untuk rule yang diizinkan.
- [ ] Patch berupa diff.
- [ ] Pemilik kode menyetujui.
- [ ] Developer review dilakukan.
- [ ] Regression test lulus.
- [ ] Scan ulang dilakukan.
- [ ] Rollback tersedia.

## Secrets

- [ ] Tidak ada private key di kode.
- [ ] Tidak ada seed phrase di kode.
- [ ] Tidak ada API key di log.
- [ ] Secret redaction aktif.
- [ ] Environment guard aktif.

## Audit

- [ ] Semua aktivitas tercatat.
- [ ] Approval tercatat.
- [ ] Rollback tercatat.
- [ ] Tidak ada perubahan policy oleh AI.
