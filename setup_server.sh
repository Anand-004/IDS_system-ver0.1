#!/bin/bash

echo "=========================================="
echo "   🛡️ STARTING IDS SERVER SETUP"
echo "=========================================="

# 1. Update & Install System Tools
echo "[*] Updating System & Installing Python..."
sudo apt update
sudo apt install -y python3-pip python3-venv ufw

# 2. Configure Firewall (CRITICAL for Server)
echo "[*] Configuring Firewall..."
sudo ufw allow 5000/tcp
echo "[+] Port 5000 opened for Dashboard access."

# 3. Create Virtual Environment
if [ ! -d "venv" ]; then
    echo "[*] Creating Virtual Environment (venv)..."
    python3 -m venv venv
else
    echo "[!] 'venv' folder already exists. Skipping creation."
fi

# 4. Install Python Libraries
echo "[*] Installing Server Dependencies..."
source venv/bin/activate

# Install Flask (Web Server) + Data Tools
pip install --upgrade pip
pip install flask pandas scapy joblib scikit-learn requests

if [ $? -eq 0 ]; then
    echo "[+] Dependencies installed successfully!"
else
    echo "[-] Error installing dependencies. Check internet."
    exit 1
fi

# 5. Make Run Scripts Executable
chmod +x run_server.sh
chmod +x run_sensor.sh

echo ""
echo "=========================================="
echo "   ✅ SERVER READY! 🚀"
echo "=========================================="
echo "1. Run the server: ./run_server.sh"
echo "2. Check your IP:  ip a"
echo "3. Open in Browser: http://<YOUR_IP>:5000"
echo ""
