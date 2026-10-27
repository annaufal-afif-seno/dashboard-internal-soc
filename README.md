# Internal SOC Incident Triage Dashboard

Sistem Dashboard Internal SOC dan Pipeline Triage Insiden Keamanan (Wazuh ASOC).

## Struktur Repositori

```text
wazuh-alert-grouping/
├── config/              # Konfigurasi rule mapping, asset, setting
├── dashboard/           # Antarmuka Pengguna React (Vite + Tailwind CSS)
│   ├── public/          # Aset statis & logo
│   ├── src/             # Komponen React & view modul
│   ├── package.json     # Konfigurasi dependensi frontend
│   └── vite.config.js   # Vite build config
├── database/            # DDL PostgreSQL schema & file migrasi
├── docs/                # Dokumentasi arsitektur, spesifikasi, dan SOP
├── pipeline/            # API FastAPI, ML classifier, scoring, correlate, LLM triage
├── reports/             # Laporan analisis & evaluasi
├── ruleset/             # Rule XML, CDB lists, dan dokumen referensi
├── scripts/             # Skrip operasional SOC, partitioning, & investigasi
│   ├── ops/             # Skrip automasi operasional
│   └── investigations/  # Skrip investigasi & audit forensik
├── tests/               # Unit & integration tests (pytest)
├── .env.example         # Template konfigurasi environment backend
├── requirements.txt     # Dependensi Python
├── README.md            # Dokumentasi utama repositori
└── run_dashboard.bat    # Skrip otomatis menjalankan backend & frontend
```

## Cara Menjalankan

### 1. Menjalankan Sekaligus (Windows)
Cukup jalankan file batch:
```cmd
run_dashboard.bat
```

### 2. Menjalankan Backend Secara Manual
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
pip install -r requirements.txt

# Salin env jika belum ada
copy .env.example .env

# Jalankan server API
python -m uvicorn pipeline.api:app --host 127.0.0.1 --port 8000 --reload
```
Akses API Docs: `http://127.0.0.1:8000/docs`

### 3. Menjalankan Frontend Secara Manual
```bash
cd dashboard
npm install
npm run dev
```
Akses UI Dashboard: `http://localhost:5173`
