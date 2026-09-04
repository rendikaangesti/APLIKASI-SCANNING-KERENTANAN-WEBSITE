@echo off
title DjoeraganCyber Security Suite - Launcher
echo ========================================================
echo   Memulai DjoeraganCyber Security Suite (Full-Stack)
echo ========================================================
echo 1. Menjalankan Backend FastAPI (Port 8000)...
start "DjoeraganCyber Backend" cmd /k "%~dp0start-backend.bat"

:: Tunggu 3 detik agar backend menginisialisasi database
ping 127.0.0.1 -n 4 >nul 2>&1

echo 2. Menjalankan Frontend Vite (Port 3000)...
start "DjoeraganCyber Frontend" cmd /k "%~dp0start-frontend.bat"

echo ========================================================
echo   Aplikasi sedang berjalan!
echo   Buka browser di: http://localhost:3000
echo ========================================================
ping 127.0.0.1 -n 3 >nul 2>&1
start http://localhost:3000
