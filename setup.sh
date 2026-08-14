#!/usr/bin/env bash
# Quick setup script for defacement-monitor
set -e

echo "[*] Creating virtual environment..."
python3 -m venv venv

echo "[*] Activating venv and installing dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo ""
echo "[+] Setup complete. Activate your venv with:"
echo "    source venv/bin/activate"
echo ""
echo "Then add your first URL:"
echo "    python defacement_monitor.py add https://example.gov.in --label 'My Site'"
echo "    python defacement_monitor.py baseline --all"
echo "    python defacement_monitor.py check --all --diff"
