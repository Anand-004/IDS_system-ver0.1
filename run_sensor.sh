#!/bin/bash

# Get the directory of the project
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "[*] Starting Network Sensor..."

# CRITICAL FIX: Go into the 'sensor' folder so Python can find the .pkl models
cd "$DIR/sensor"

# Run Python using the virtual environment (which is one folder up)
sudo "$DIR/venv/bin/python3" "ids_agent.py"
