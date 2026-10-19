# RUNBOOK OPERASIONAL SISTEM & PEMELIHARAAN INFRASTRUKTUR
## *Operations, Deployment, Database Maintenance & Troubleshooting Runbook*

---

### 1. IKHTISAR RUNBOOK
Runbook ini memuat panduan teknis operasional bagi Security Platform Engineers dan Database Administrators (DBA) untuk melakukan deployment, migrasi skema, manajemen partisi bulanan, pemecahan masalah (*troubleshooting*), dan prosedur pemulihan bencana (*Disaster Recovery*).

---

### 2. PANDUAN DEPLOYMENT & INISIALISASI LINGKUNGAN

#### Prasyarat Sistem:
* Python 3.10+ (dengan package `psycopg2-binary`, `pydantic`, `pytest`)
* PostgreSQL 14+ Server aktif di port 5432
* Wazuh Manager 4.x

#### Langkah Inisialisasi:
1. **Clone repositori dan install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```
2. **Inisialisasi Database & Migrasi Skema 19 Tabel:**
   ```powershell
   python scripts/setup_postgres.py
   ```
3. **Validasi Kesiapan Pipeline (Automated Unit Test Suite):**
   ```powershell
   python -m pytest tests/ -v
   ```

---

### 3. PROSEDUR PEMELIHARAAN DATABASE & ROTASI PARTISI BULANAN

Tabel `telemetry.raw_events` dan `telemetry.normalized_events` menggunakan partisi rentang bulanan. Database dilengkapi dengan stored procedure otomatis:

#### A. Membuat Partisi Bulan Depan Secara Otomatis:
Jalankan query ini setiap tanggal 25 setiap bulannya:
```sql
SELECT telemetry.create_monthly_partitions(2);
```
*Fungsi:* Otomatis membuat tabel partisi `raw_events_YYYY_MM` dan `normalized_events_YYYY_MM` untuk 2 bulan ke depan beserta seluruh indeksnya.

#### B. Menghapus / Rotasi Partisi yang Melewati Batas Retensi:
Jalankan query ini untuk membersihkan data lama sesuai kebijakan retensi (contoh: retensi 90 hari):
```sql
SELECT telemetry.purge_expired_partitions(90);
```
*Fungsi:* Men-detach partisi lama dari master tabel dan melakukan `DROP TABLE` secara aman tanpa menyebabkan tabel locking.

---

### 4. EKSEKUSI PIPELINE INGESTION TELEMETRI

#### A. Mode Streaming In-Memory (Benchmark & Profiling):
```powershell
python run_pipeline.py
```
*Output:* Memproses 840.402 log dalam ~115 detik, mencetak ringkasan reduksi kebisingan (97,75%) dan deteksi insiden tanpa menulis ke database.

#### B. Mode Direct Database Persistence:
```powershell
python run_pipeline.py --persist-db
```
*Output:* Mengalirkan seluruh log mentah ke `telemetry.raw_events`, normalisasi ke `telemetry.normalized_events`, objek terkompresi ke `suppression.aggregated_alerts`, dan tiket insiden ke `soc_ops.soc_triage_queue`.

---

### 5. PANDUAN TROUBLESHOOTING KENDALA OPERASIONAL

| Gejala Kendala (*Symptom*) | Akar Masalah (*Root Cause*) | Tindakan Korektif (*Fix Action*) |
| :--- | :--- | :--- |
| `relation "raw_events" does not exist` di pgAdmin | Kursor query aktif di skema yang salah (bukan `telemetry`). | Jalankan `SET search_path TO telemetry, enrichment, suppression, correlation, risk_engine, soc_ops, metrics, public;` atau gunakan prefix `telemetry.raw_events`. |
| Connection Pool Exhaustion (`pool exhausted`) | Beban worker melebihi kapasitas `maxconn=10`. | Tingkatkan `maxconn` di `config/settings.py` atau periksa apakah ada koneksi yang lupa ditutup (`with db.get_connection():`). |
| Reduksi kebisingan menurun drastis (< 90%) | Muncul signature bot baru yang belum terdaftar di S2 atau sliding window expired. | Review log di `suppression.aggregated_alerts` dan daftarkan aturan S2 baru melalui form supresi. |
| Ingestion throughput melambat (< 2.000 log/dtk) | Indeks database mengalami fragmentasi atau autovacuum tertunda. | Jalankan perintah maintenance PostgreSQL: `VACUUM ANALYZE telemetry.raw_events;`. |
