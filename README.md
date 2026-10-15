# Internal SOC Incident Triage Dashboard

Sistem Dashboard Internal SOC dan Pipeline Triage Insiden Keamanan (Wazuh ASOC).

## Struktur Repositori

```text
dashboard-internal-soc/
├── backend/
│   ├── config/              # Konfigurasi rule mapping, asset, setting
│   ├── database/            # DDL PostgreSQL schema & file migrasi
│   ├── pipeline/            # API FastAPI, ML classifier, scoring, correlate, LLM triage
│   ├── scripts/             # Skrip operasional SOC & retention
│   ├── .env.example         # Template konfigurasi environment backend
│   └── requirements.txt     # Dependensi Python
├── frontend/
│   ├── public/              # Aset statis & logo
│   ├── src/                 # Komponen React (Vite + Tailwind CSS)
│   ├── package.json         # Konfigurasi dependensi frontend
│   └── vite.config.js       # Vite build config
├── .gitignore
├── README.md
└── run_dashboard.bat        # Skrip otomatis menjalankan backend & frontend
```

## Cara Menjalankan

### 1. Menjalankan Sekaligus (Windows)
Cukup jalankan file batch:
```cmd
run_dashboard.bat
```

### 2. Menjalankan Backend Secara Manual
```bash
cd backend
python -m venv venv
# Windows:
venv\Scripts\activate
pip install -r requirements.txt

# Salin env
copy .env.example .env

# Jalankan server
python -m uvicorn pipeline.api:app --host 127.0.0.1 --port 8000 --reload
```
Akses API Docs: `http://127.0.0.1:8000/docs`

### 3. Menjalankan Frontend Secara Manual
```bash
cd frontend
npm install
npm run dev
```
Akses UI Dashboard: `http://localhost:5173`
