@echo off
title Wazuh SOC React Dashboard
cd /d "%~dp0..\..\dashboard"
echo ===================================================
echo   Starting Wazuh SOC React Vite Dashboard
echo   URL: http://localhost:5173
echo ===================================================
npm run dev
pause
