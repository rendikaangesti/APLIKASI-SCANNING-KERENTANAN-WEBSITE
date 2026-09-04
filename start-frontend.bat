@echo off
title DjoeraganCyber - Frontend Web UI (Vite)
echo ========================================================
echo   DjoeraganCyber Security Suite - Frontend UI
echo ========================================================

cd /d "%~dp0frontend"

:: Periksa apakah npm tersedia
where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] npm/Node.js tidak ditemukan di PATH sistem.
    echo Silakan pastikan Node.js sudah terinstal.
    pause
    exit /b 1
)

echo Menjalankan Frontend Vite di http://localhost:3000 ...
npm run dev

pause
