# PANDUAN DEPLOYMENT TERPADU & STANDAR OPERASIONAL (ZERO-ERROR MANUAL)
## SISTEM DASHBOARD INTERNAL SOC (WAZUH ASOC PIPELINE)

> Dokumen ini disusun secara deterministik berdasarkan seluruh riwayat *hands-on* dan penyelesaian *real-world errors* (masalah dependensi, permission volume Docker, miskonfigurasi IP Vector, hardcoded socket, hingga sinkronisasi hash otentikasi). Setiap tahapan wajib dijalankan berurutan agar sistem siap pakai tanpa error lanjutan.

---

## DAFTAR ISI
1. [Topologi Jaringan & Prasyarat Lingkungan](#1-topologi-jaringan--prasyarat-lingkungan)
2. [Tahap 1: Persiapan OS & Perbaikan Error Paket di VM Dashboard](#tahap-1-persiapan-os--perbaikan-error-paket-di-vm-dashboard)
3. [Tahap 2: Instalasi & Konfigurasi Basis Data PostgreSQL](#tahap-2-instalasi--konfigurasi-basis-data-postgresql)
4. [Tahap 3: Clone Repositori & Hak Akses Direktori](#tahap-3-clone-repositori--hak-akses-direktori)
5. [Tahap 4: Konfigurasi & Dependensi Backend (FastAPI + Python)](#tahap-4-konfigurasi--dependensi-backend-fastapi--python)
6. [Tahap 5: Konfigurasi & Build Frontend (React + Vite + Reverse Proxy)](#tahap-5-konfigurasi--build-frontend-react--vite--reverse-proxy)
7. [Tahap 6: Otomatisasi Service Background dengan PM2](#tahap-6-otomatisasi-service-background-dengan-pm2)
8. [Tahap 7: Konfigurasi VM Wazuh & Pengiriman Log via Vector](#tahap-7-konfigurasi-vm-wazuh--pengiriman-log-via-vector)
9. [Tahap 8: Verifikasi End-to-End & Uji Coba Alert Kritis](#tahap-8-verifikasi-end-to-end--uji-coba-alert-kritis)
10. [Troubleshooting Matrix: Rangkuman Error Hands-on & Solusinya](#10-troubleshooting-matrix-rangkuman-error-hands-on--solusinya)
11. [Kredensial Akses Resmi](#11-kredensial-akses-resmi)

---

## 1. Topologi Jaringan & Prasyarat Lingkungan

| Node / Komponen | Alamat IP | Sistem Operasi | Peran & Layanan |
| :--- | :--- | :--- | :--- |
| **VM Wazuh** | `192.168.0.101` | Linux (Ubuntu/Debian) | Wazuh Manager (Docker Single-Node) + Vector Log Shipper |
| **VM Dashboard** | `192.168.0.103` | Ubuntu 24.04 LTS (Noble) | PostgreSQL 16 (Port 5432), FastAPI (Port 8000), Vite (Port 5173) |
| **Host Workstation** | `192.168.0.x` | Windows / macOS | Browser SOC Analyst untuk mengakses UI |

---

## Tahap 1: Persiapan OS & Perbaikan Error Paket di VM Dashboard

Lakukan SSH ke VM Dashboard:
```bash
ssh afif@192.168.0.103
```

### 1.1. Perbaikan Sumber Repository CD-ROM & Broken DPKG
Pada instalasi fresh ISO Ubuntu 24.04, sering terjadi penguncian `dpkg` dan kegagalan update karena file `/cdrom` masih aktif.

Jalankan perintah mitigasi berikut:
```bash
# Hapus sumber cdrom yang sudah tidak ter-mount
sudo sed -i '/cdrom/d' /etc/apt/sources.list
sudo sed -i '/cdrom/d' /etc/apt/sources.list.d/*.sources 2>/dev/null
sudo sed -i '/cdrom/d' /etc/apt/sources.list.d/*.list 2>/dev/null

# Selesaikan paket yang terinterupsi (contoh: vim/vim-runtime)
sudo dpkg --configure -a
sudo apt --fix-broken install -y
sudo apt update && sudo apt upgrade -y
```

### 1.2. Instalasi Paket Sistem, Compiler, dan Runtime
Jalankan instalasi pustaka kompilasi agar driver database (`psycopg2`) dan pustaka ML (`lightgbm`) dapat terpasang sempurna:
```bash
# Tambahkan repo Node.js 20 LTS
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -

# Pasang paket pengembangan
sudo apt install -y \
  git \
  python3 \
  python3-pip \
  python3-venv \
  python3-dev \
  libpq-dev \
  build-essential \
  nodejs \
  postgresql \
  postgresql-contrib \
  curl \
  ufw

# Pasang PM2 Process Manager secara global
sudo npm install -g pm2
```

---

## Tahap 2: Instalasi & Konfigurasi Basis Data PostgreSQL

### 2.1. Menyalakan & Mengaktifkan Layanan PostgreSQL
Pastikan service berjalan:
```bash
sudo systemctl enable --now postgresql
sudo systemctl status postgresql
```

### 2.2. Membuat Database & Menetapkan Hak Akses
Masuk ke sub-shell user `postgres`:
```bash
sudo -u postgres psql
```
Eksekusi baris SQL berikut secara berurutan:
```sql
-- Tetapkan password untuk pengguna postgres
ALTER USER postgres WITH PASSWORD 'postgres';

-- Buat database wazuh_soc_db dengan owner postgres
CREATE DATABASE wazuh_soc_db OWNER postgres;

-- Berikan semua hak akses
GRANT ALL PRIVILEGES ON DATABASE wazuh_soc_db TO postgres;

-- Keluar dari psql
\q
```

### 2.3. Membuka Akses Koneksi Remote (Opsional / Multi-Host Monitoring)
Edit `/etc/postgresql/16/main/postgresql.conf`:
```bash
sudo sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/g" /etc/postgresql/16/main/postgresql.conf
sudo sed -i "s/listen_addresses = 'localhost'/listen_addresses = '*'/g" /etc/postgresql/16/main/postgresql.conf
```
Tambahkan izin autentikasi di `/etc/postgresql/16/main/pg_hba.conf`:
```bash
echo "host all all 0.0.0.0/0 scram-sha-256" | sudo tee -a /etc/postgresql/16/main/pg_hba.conf
sudo systemctl restart postgresql
```

---

## Tahap 3: Clone Repositori & Hak Akses Direktori

> **PENTING**: Folder `/opt` secara default berhak akses `root:root`. Untuk mencegah error `EACCES: permission denied` saat `npm install` atau penulisan log Python, kepemilikan folder wajib diserahkan kepada pengguna aktif (`afif`).

```bash
# Masuk ke direktori /opt
cd /opt

# Clone repositori bersih
sudo git clone https://github.com/annaufal-afif-seno/dashboard-internal-soc.git

# Berikan hak kepemilikan penuh kepada user afif
sudo chown -R afif:afif /opt/dashboard-internal-soc
cd /opt/dashboard-internal-soc
```

---

## Tahap 4: Konfigurasi & Dependensi Backend (FastAPI + Python)

### 4.1. Eksekusi Skema Database Lengkap
Sebelum menjalankan backend, struktur tabel SIEM wajib dimasukkan ke database:
```bash
cd /opt/dashboard-internal-soc/backend

# Inisialisasi 19 tabel, ekstensi UUID & trigram, serta partisi telemetry
psql -U postgres -h 127.0.0.1 -d wazuh_soc_db -f database/complete_schema.sql

# Inisialisasi master data aset, identitas, dan aturan korelasi
psql -U postgres -h 127.0.0.1 -d wazuh_soc_db -f database/seed_data.sql
```
*(Saat diminta password, masukkan `postgres`)*

### 4.2. Setup Virtual Environment Python & Paket Lengkap
Untuk menghindari error runtime seperti `ModuleNotFoundError: No module named 'dateutil'`, pasang seluruh pustaka berikut di dalam environment terisolasi:

```bash
cd /opt/dashboard-internal-soc/backend

# Buat virtual environment
python3 -m venv venv

# Aktifkan virtual environment
source venv/bin/activate

# Upgrade pip & install semua paket pipeline
pip install --upgrade pip
pip install -r requirements.txt
pip install \
  uvicorn \
  fastapi \
  lightgbm \
  scikit-learn \
  python-dateutil \
  requests \
  bcrypt \
  polars \
  rich \
  python-dotenv \
  pydantic \
  psycopg2-binary
```

### 4.3. Siapkan Konfigurasi `.env`
Salin template environment:
```bash
cp .env.example .env
```
Pastikan variabel kunci terisi seperti berikut di `.env`:
```env
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=wazuh_soc_db
DB_USER=postgres
DB_PASSWORD=postgres
ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://192.168.0.103:5173
```

---

## Tahap 5: Konfigurasi & Build Frontend (React + Vite + Reverse Proxy)

### 5.1. Instalasi Modul Frontend
Masuk ke subdirektori `frontend`:
```bash
cd /opt/dashboard-internal-soc/frontend
npm install
```

### 5.2. Konfigurasi Reverse Proxy Vite (`vite.config.js`)
Agar frontend yang dibuka dari browser mana pun tidak mencari `localhost:8000` di mesin pengguna, gunakan konfigurasi proxy bawaan Vite pada `/opt/dashboard-internal-soc/frontend/vite.config.js`:

```javascript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true, // Mengikat ke 0.0.0.0 agar dapat diakses via IP LAN
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
});
```
*(Catatan: Di kode sumber komponen `.jsx`, semua pemanggilan API menggunakan relative path seperti `/api/metrics/overview` tanpa menyertakan awalan `http://localhost:8000`)*.

---

## Tahap 6: Otomatisasi Service Background dengan PM2

Gunakan skrip wrapper bash agar proses tidak mati ketika terminal SSH ditutup.

### 6.1. Buat Skrip Eksekusi Backend (`/opt/dashboard-internal-soc/backend/start.sh`)
```bash
cat << 'EOF' > /opt/dashboard-internal-soc/backend/start.sh
#!/bin/bash
cd /opt/dashboard-internal-soc/backend
source venv/bin/activate
exec uvicorn pipeline.api:app --host 0.0.0.0 --port 8000
EOF

chmod +x /opt/dashboard-internal-soc/backend/start.sh
```

### 6.2. Buat Skrip Eksekusi Frontend (`/opt/dashboard-internal-soc/frontend/start.sh`)
```bash
cat << 'EOF' > /opt/dashboard-internal-soc/frontend/start.sh
#!/bin/bash
cd /opt/dashboard-internal-soc/frontend
exec npm run dev -- --host 0.0.0.0
EOF

chmod +x /opt/dashboard-internal-soc/frontend/start.sh
```

### 6.3. Daftarkan ke PM2 & Simpan State Autostart
```bash
pm2 delete all 2>/dev/null || true
pm2 start /opt/dashboard-internal-soc/backend/start.sh --name soc-backend
pm2 start /opt/dashboard-internal-soc/frontend/start.sh --name soc-frontend

pm2 save
sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u afif --hp /home/afif
```

### 6.4. Verifikasi Port Aktif
Periksa apakah port telah terbuka dan melayani koneksi:
```bash
sudo ss -tlpn | grep -E '8000|5173|5432'
```
*Port `8000` (FastAPI), `5173` (Frontend Vite), dan `5432` (PostgreSQL) harus berstatus `LISTEN`.*

---

## Tahap 7: Konfigurasi VM Wazuh & Pengiriman Log via Vector

Lakukan SSH ke VM Wazuh:
```bash
ssh afif@192.168.0.101
```

### 7.1. Buka Izin Akses Baca Volume Docker Wazuh
File alert Wazuh berada di volume Docker yang secara default hanya bisa dibaca oleh `root`. Berikan hak akses kepada pengguna `vector`:
```bash
# Masukkan user vector ke grup docker
sudo usermod -aG docker vector

# Berikan izin traversal pada path volume
sudo chmod +rx /var/lib/docker /var/lib/docker/volumes
sudo chmod -R +r /var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/
```

### 7.2. Konfigurasi File Shipper Vector (`/etc/vector/vector.yaml`)
Pastikan endpoint sink mengarah ke alamat IP VM Dashboard (`192.168.0.103:8000`):

```yaml
data_dir: "/var/lib/vector"

# 1. SOURCES: Membaca log Wazuh langsung dari Docker volume di VM
sources:
  wazuh_alerts:
    type: "file"
    include:
      - "/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json"
    read_from: "beginning"
    fingerprint:
      strategy: "device_and_inode"
    max_line_bytes: 2097152

# 2. TRANSFORMS: Parsing string menjadi JSON murni
transforms:
  parse_wazuh_json:
    type: "remap"
    inputs:
      - "wazuh_alerts"
    source: |
      parsed, err = parse_json(.message)
      if err == null {
        . = parsed
      }

# 3. SINKS: Mengirim stream ke Ingestion API VM Dashboard
sinks:
  to_soc_pipeline:
    type: "http"
    inputs:
      - "parse_wazuh_json"
    uri: "http://192.168.0.103:8000/api/v1/ingest/alerts-stream"
    method: "post"
    compression: "gzip"
    encoding:
      codec: "json"
    batch:
      max_events: 1000
      timeout_secs: 1
    buffer:
      type: "disk"
      max_size: 10737418240              # Buffer disk 10 GB (proteksi anti-drop saat lonjakan alert)
      when_full: "block"
    request:
      retry_attempts: 999999
      retry_initial_backoff_secs: 1
      retry_max_duration_secs: 30
```

### 7.3. Validasi & Restart Vector
```bash
vector validate --config /etc/vector/vector.yaml
sudo systemctl restart vector
sudo systemctl status vector
```

---

## Tahap 8: Verifikasi End-to-End & Uji Coba Alert Kritis

### 8.1. Simulasi Alert Kritis (Level 14 - Web Shell RCE)
Jalankan perintah ini di VM Wazuh (`192.168.0.101`) untuk menyuntikkan alert ke aliran Wazuh:
```bash
sudo bash -c 'cat <<EOF >> /var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json
{"timestamp":"2026-10-15T09:05:00.000+0000","rule":{"level":14,"description":"CRITICAL ATTACK: Remote Code Execution via Web Shell detected","id":"31301","firedtimes":1},"agent":{"id":"005","name":"web-ecommerce-prod","ip":"192.168.0.150"},"manager":{"name":"wazuh-manager"},"id":"1792049999.8888","decoder":{"name":"web-accesslog"},"data":{"srcip":"45.33.32.156","srcport":"54321","dstip":"192.168.0.150","dstport":"443","srcuser":"nobody"},"location":"/var/log/nginx/access.log"}
EOF'
```

### 8.2. Pembuktian di VM Dashboard (`192.168.0.103`)
Kembali ke VM Dashboard, cek apakah data langsung terdaftar di database:
```bash
# 1. Cek jumlah data raw events
sudo -u postgres psql -d wazuh_soc_db -c "SELECT count(*) FROM telemetry.raw_events;"

# 2. Cek baris alert kritis yang baru masuk
sudo -u postgres psql -d wazuh_soc_db -c "SELECT event_id, agent_name, source_ip, ingested_at FROM telemetry.raw_events ORDER BY ingested_at DESC LIMIT 1;"

# 3. Cek hasil normalisasi
sudo -u postgres psql -d wazuh_soc_db -c "SELECT rule_id, rule_level, rule_description FROM telemetry.normalized_events ORDER BY processed_at DESC LIMIT 1;"
```
*Hasil yang diharapkan: Menampilkan `rule_id = 31301`, `rule_level = 14`, dan `event_id = 1792049999.8888`.*

---

## 10. Troubleshooting Matrix: Rangkuman Error Hands-on & Solusinya

Berikut rangkuman setiap kendala yang ditemui saat implementasi beserta akar masalah dan instruksi penanganannya:

| No | Gejala / Pesan Error | Penyebab Utama | Solusi Pasti |
| :--- | :--- | :--- | :--- |
| **1** | `E: The repository 'file:/cdrom noble Release' no longer has a Release file.` | File ISO Ubuntu saat instalasi sudah dilepas, tetapi APT masih mencoba membacanya. | Jalankan `sudo sed -i '/cdrom/d' /etc/apt/sources.list*` lalu `sudo apt update`. |
| **2** | `E: dpkg was interrupted, you must manually run 'sudo dpkg --configure -a'` | Proses instalasi sebelumnya terputus di tengah jalan. | Jalankan `sudo dpkg --configure -a` lalu `sudo apt --fix-broken install -y`. |
| **3** | `npm error EACCES: permission denied, open 'package-lock.json'` | Direktori `/opt/dashboard-internal-soc` dimiliki oleh user `root`. | Berikan kepemilikan ke user login: `sudo chown -R afif:afif /opt/dashboard-internal-soc`. |
| **4** | `ModuleNotFoundError: No module named 'dateutil'` | Pustaka `python-dateutil` belum ada di virtual environment backend. | Jalankan `pip install python-dateutil` di dalam venv Python backend. |
| **5** | Vector `Healthcheck error: connection refused` | IP pada `vector.yaml` di VM Wazuh mengarah ke `192.168.1.103` (subnet berbeda). | Ubah URI di `/etc/vector/vector.yaml` menjadi `http://192.168.0.103:8000/api/v1/ingest/alerts-stream`. |
| **6** | Total Alert di database tetap `0` padahal Vector aktif | Pengguna `vector` tidak diizinkan membaca file di `/var/lib/docker/volumes/...`. | Masukkan user vector ke grup docker: `sudo usermod -aG docker vector && sudo chmod +rx /var/lib/docker /var/lib/docker/volumes`. |
| **7** | Browser menampilkan angka statis / gagal load data | Frontend sebelumnya memanggil `http://localhost:8000` di mana `localhost` adalah PC pengguna. | Gunakan relative path `/api/...` di komponen React dan konfigurasikan reverse proxy di `vite.config.js`. |
| **8** | PM2 Uvicorn error `SyntaxError: Invalid or unexpected token` | PM2 mencoba menjalankan skrip binari Python dengan engine Node.js. | Buat wrapper shell script `start.sh` berisikan `source venv/bin/activate && exec uvicorn ...` lalu jalankan via PM2. |
| **9** | Pesan login: `Kredensial tidak valid. Username atau kata sandi salah.` | Hash kata sandi di tabel `soc_ops.soc_users` belum sinkron atau berbeda salt. | Generate hash SHA-256 / bcrypt untuk `WazuhSecOps2026!` dan update ke tabel `soc_ops.soc_users`. |

---

## 11. Kredensial Akses Resmi

Akses Dashboard melalui browser web:
👉 **`http://192.168.0.103:5173`**

### Daftar Akun Operasional:

| Username | Kata Sandi | Role Hak Akses | Deskripsi Peran |
| :--- | :--- | :--- | :--- |
| **`admin_secops`** | `WazuhSecOps2026!` | **ADMIN** | Akses penuh manajemen insiden, RBAC, metrik database, dan tuning rule. |
| **`dev_bunga`** | `WazuhSecOps2026!` | **SOC DEVELOPER** | Akses pengembangan model LightGBM, dataset ground truth, dan korelasi. |
| **`dev_dimas`** | `WazuhSecOps2026!` | **SOC MANAGER** | Akses tinjauan tiket, eskalasi SLA incident queue, dan persetujuan penindakan. |

*(Catatan: Karakter tanda seru `!` di akhir kata sandi adalah bagian dari password yang valid)*.
