@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================
echo   Baoyan System - starting
echo ============================================

python -c "import flask" 2>nul
if errorlevel 1 (
    echo [1/2] Installing Flask ...
    python -m pip install flask
)

if not exist "instance\baoyan.db" (
    echo [2/2] Generating demo data ...
    python seed.py
)

echo.
echo   Open browser: http://127.0.0.1:5000
echo   Student 2023010101 / Counselor T2001 / Admin A1001
echo   Password: wt2026
echo.
echo   Press Ctrl+C to stop the server.
echo.

python app.py
pause
