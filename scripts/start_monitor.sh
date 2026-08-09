#!/bin/bash
cd "$(dirname "$0")/.."
if pgrep -f "keep_running.sh" > /dev/null; then
    echo "Monitor already running."
    ps aux | grep keep_running | grep -v grep
else
    echo "Starting monitor..."
    nohup ./keep_running.sh &
    echo "Monitor started (PID: $!)"
fi
