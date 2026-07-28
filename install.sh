#!/bin/bash
# Author: Manmohan (Mike) Bains -- Watchdog
echo "=== WATCHDOG INSTALLER ==="
pip3 install fastapi uvicorn --break-system-packages
git clone https://github.com/mikebains41-debug/Watchdog.git
cd Watchdog
mkdir -p watchdog_data
echo "=== WATCHDOG INSTALLED ==="
echo "Run: python3 watchdog.py --api"
echo "Run: python3 watchdog.py --test"
