@echo off
title Wazuh SOC FastAPI Backend
cd /d "%~dp0..\.."
echo ===================================================
echo   Starting Wazuh SOC FastAPI REST Backend
echo   URL: http://localhost:8000
echo   Docs: http://localhost:8000/docs
echo ===================================================
python -m uvicorn pipeline.api:app --host 0.0.0.0 --port 8000 --reload
pause
