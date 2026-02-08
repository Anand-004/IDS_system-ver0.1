#!/bin/bash

# Get the directory where this script is saved
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "[*] Starting IDS Dashboard..."

# Activate 'venv' (NOT ids_env)
source "$DIR/venv/bin/activate"

# Run the App
python3 "$DIR/server/app.py"
