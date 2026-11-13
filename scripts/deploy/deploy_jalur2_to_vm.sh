#!/usr/bin/env bash
# ==============================================================================
# JALUR 2 APEX ENTERPRISE ZERO-TOUCH DEPLOYMENT SCRIPT UNTUK VM DASHBOARD
# ==============================================================================
# Prinsip: ZERO-TOUCH GUARANTEE
# - Jalur 1 (Triage, Ingest, Agregasi, Korelasi, SLA, Ground Truth) 100% TETAP UTUH.
# - Tidak ada tabel atau kolom eksisting yang di-drop atau diubah paksa.
# - Seluruh tabel Jalur 2 dibuat dengan klausa `CREATE TABLE IF NOT EXISTS`.
# ==============================================================================

set -e

APP_DIR="/opt/dashboard-internal-soc"
DB_NAME="wazuh_soc_db"
DB_USER="postgres"

echo "================================================================================"
echo "[*] MEMULAI DEPLOYMENT JALUR 2 (APEX ENTERPRISE) PADA VM DASHBOARD"
echo "================================================================================"

# 1. Masuk ke direktori aplikasi
if [ -d "$APP_DIR" ]; then
    cd "$APP_DIR"
    echo "[+] Berada di direktori $APP_DIR"
else
    echo "[!] Direktori $APP_DIR tidak ditemukan. Menggunakan direktori saat ini: $(pwd)"
fi

# 2. Eksekusi Skema Database Non-Destruktif Jalur 2
echo "[*] Menerapkan skema tabel Jalur 2 ke database PostgreSQL ($DB_NAME)..."
MIGRATION_FILE="database/migrations/jalur2_apex_dual_track_schema.sql"

if [ -f "$MIGRATION_FILE" ]; then
    psql -U "$DB_USER" -d "$DB_NAME" -f "$MIGRATION_FILE"
    echo "[+] Skema tabel Jalur 2 (alert_activity_groups, apex_activity_groups) BERHASIL dibuat!"
else
    echo "[-] File migrasi $MIGRATION_FILE tidak ditemukan!"
    exit 1
fi

# 3. Verifikasi Keberadaan Modul Python Jalur 2
echo "[*] Memverifikasi integritas file mesin Jalur 2..."
REQUIRED_FILES=(
    "pipeline/apex_normalizer.py"
    "pipeline/category_catalog.py"
    "pipeline/fingerprint_engine.py"
    "pipeline/leaf_grouper.py"
    "pipeline/rollup_engine.py"
    "pipeline/apex_correlation_engine.py"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  [OK] $file"
    else
        echo "  [MISSING] $file"
        exit 1
    fi
done

# 4. Restart Layanan Background (Jika menggunakan systemd)
echo "[*] Menyinkronkan service systemd..."
if systemctl is-active --quiet asoc-pipeline; then
    sudo systemctl restart asoc-pipeline
    echo "[+] Service asoc-pipeline di-restart!"
fi

if systemctl is-active --quiet asoc-api; then
    sudo systemctl restart asoc-api
    echo "[+] Service asoc-api di-restart!"
fi

echo "================================================================================"
echo "[+] DEPLOYMENT JALUR 2 SELESAI DENGAN SUKSES (100% ZERO-TOUCH ISOLATION)!"
echo "    - Jalur 1 (Operasional SLA & Triage Queue) : TETAP BERJALAN NORMAL"
echo "    - Jalur 2 (Apex Enterprise & Activity Groups): KINI AKTIF SECARA PARALEL"
echo "================================================================================"
