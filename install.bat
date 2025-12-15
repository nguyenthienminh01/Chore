@echo off
echo ====================================
echo   WiFi Security Checker Installer
echo ====================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python chua duoc cai dat!
    echo Vui long cai dat Python tu https://python.org
    pause
    exit /b 1
)

echo [1/2] Dang cai dat cac thu vien can thiet...
pip install -r requirements.txt

echo.
echo [2/2] Cai dat hoan tat!
echo.
echo Chay "run.bat" de khoi dong ung dung.
echo.
pause
