#!/bin/bash

echo "=========================================="
echo "   🚀 STARTING IDS SENSOR SETUP"
echo "=========================================="

# 1. Update & Install System Tools (Requires Password)
echo "[*] Updating System & Installing Python..."
sudo apt update
sudo apt install -y python3-pip python3-venv

# 2. Create Virtual Environment
if [ ! -d "venv" ]; then
    echo "[*] Creating Virtual Environment (venv)..."
    python3 -m venv venv
else
    echo "[!] 'venv' folder already exists. Skipping creation."
fi

# 3. Install Python Libraries inside venv
echo "[*] Installing Python Libraries..."

# Activate venv to install locally
source venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install flask scapy pandas joblib scikit-learn requests

if [ $? -eq 0 ]; then
    echo "[+] Python dependencies installed successfully!"
else
    echo "[-] Error installing dependencies. Check your internet connection."
    exit 1
fi

# 4. Make Run Scripts Executable
echo "[*] Setting permissions..."
chmod +x run_sensor.sh
chmod +x run_server.sh

echo ""
echo "=========================================="
echo "   ✅ SETUP COMPLETE!"
echo "=========================================="
echo "To start the Sensor, run: ./run_sensor.sh"
