#!/bin/bash
while true; do
    cd ~/Watchdog-quantum-collab
    python3 run_all.py >> watchdog_auto.log 2>&1
    echo "--- $(date) ---" >> watchdog_auto.log
    sleep 3600   # 1 hour
done
