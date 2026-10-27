@echo off
title WAZUH ASOC DASHBOARD LAUNCHER
color 0A

echo ========================================================
echo       WAZUH ASOC ENTERPRISE DASHBOARD LAUNCHER
echo ========================================================
echo.

cd /d "%~dp0"

echo [1/3] Memulai Backend FastAPI (Port 8000)...
start "WAZUH ASOC - FastAPI Backend" cmd /k "python -m uvicorn pipeline.api:app --host 127.0.0.1 --port 8000 --reload"

timeout /t 3 /nobreak >nul

echo [2/3] Memulai Frontend React + Vite (Port 5173)...
start "WAZUH ASOC - React Frontend" cmd /k "cd dashboard && npm run dev"

timeout /t 3 /nobreak >nul

echo [3/3] Membuka Dashboard di Browser...
start http://localhost:5173

echo.
echo ========================================================
echo   DASHBOARD TELAH AKTIF!
echo   - Frontend: http://localhost:5173
echo   - Backend : http://127.0.0.1:8000
echo   - API Docs: http://127.0.0.1:8000/docs
echo   Jangan tutup jendela terminal yang baru terbuka.
echo ========================================================
echo.
pause
