@echo off
setlocal enabledelayedexpansion

echo =====================================================================
echo  Predictive Cyber Defence World Model - Launch Script
echo =====================================================================
echo.

:: 1. Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.10 or 3.11.
    pause
    exit /b 1
)

:: 2. Check Node
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH. Please install Node.js 18+.
    pause
    exit /b 1
)

echo [*] Checking and installing Python dependencies...
python -m pip install -q -r requirements.txt

echo [*] Checking frontend dependencies...
if not exist "frontend\node_modules\" (
    echo [*] Installing frontend npm packages...
    cd frontend && call npm install && cd ..
)

echo.
echo [*] Starting Cyber Defence World Model System...
echo     - Frontend Dashboard: http://localhost:3000
echo.

cd frontend
call npm run dev
cd ..
pause
