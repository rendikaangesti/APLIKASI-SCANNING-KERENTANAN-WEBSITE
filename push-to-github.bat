@echo off
title Push DjoeraganCyber Security Suite to GitHub
echo ========================================================
echo   Pushing Repository to GitHub (origin/main)
echo ========================================================
echo.

cd /d "%~dp0"

echo Memeriksa remote origin...
git remote -v
echo.

echo Mengirim commit ke GitHub...
git push -u origin main

if %errorlevel% equ 0 (
    echo.
    echo ========================================================
    echo   [BERHASIL] Seluruh kode dan README telah sukses ter-push!
    echo ========================================================
) else (
    echo.
    echo ========================================================
    echo   [GAGAL] Silakan pastikan repositori sudah dibuat di:
    echo   https://github.com/new dengan nama:
    echo   APLIKASI-SCANNING-KERENTANAN-WEBSITE
    echo ========================================================
)

pause
