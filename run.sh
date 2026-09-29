#!/usr/bin/env bash
set -e

echo "====================================================================="
echo " Predictive Cyber Defence World Model - Launch Script"
echo "====================================================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed. Please install Python 3.10 or 3.11."
    exit 1
fi

# Check Node
if ! command -v node &> /dev/null; then
    echo "[ERROR] Node.js is not installed. Please install Node.js 18+."
    exit 1
fi

echo "[*] Checking and installing Python dependencies..."
python3 -m pip install -q -r requirements.txt

echo "[*] Checking frontend dependencies..."
if [ ! -d "frontend/node_modules" ]; then
    echo "[*] Installing frontend npm packages..."
    (cd frontend && npm install)
fi

echo ""
echo "[*] Starting Cyber Defence World Model System..."
echo "    - Frontend Dashboard: http://localhost:3000"
echo ""

cd frontend
npm run dev
