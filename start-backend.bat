@echo off
title DjoeraganCyber - Backend API (FastAPI)
echo ========================================================
echo   DjoeraganCyber Security Suite - Backend Service
echo ========================================================
echo Memeriksa direktori dan environment...

cd /d "%~dp0backend"

:: Periksa apakah python tersedia
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python tidak ditemukan di PATH sistem.
    echo Silakan pastikan Python 3.10+ sudah terinstal dan terdaftar di PATH Windows.
    pause
    exit /b 1
)

echo Menjalankan Backend FastAPI di http://127.0.0.1:8000 ...
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

pause
