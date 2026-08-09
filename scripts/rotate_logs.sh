#!/bin/bash
# Rotate watchdog_auto.log if it exceeds 10MB

LOG_DIR="$HOME/Watchdog-quantum-collab"
LOG_FILE="$LOG_DIR/watchdog_auto.log"
MAX_SIZE=$((10 * 1024 * 1024))  # 10 MB

if [ -f "$LOG_FILE" ] && [ $(stat -c%s "$LOG_FILE") -gt $MAX_SIZE ]; then
    mv "$LOG_FILE" "$LOG_FILE.$(date +%Y%m%d)"
    touch "$LOG_FILE"
    echo "Rotated log at $(date)" >> "$LOG_FILE"
fi
