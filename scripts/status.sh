#!/bin/bash
cd "$(dirname "$0")/.."
echo "=== Watchdog Quantum Status ==="
if pgrep -f "keep_running.sh" > /dev/null; then
    echo "Monitor: RUNNING"
    ps aux | grep keep_running | grep -v grep
else
    echo "Monitor: STOPPED"
fi
echo ""
echo "Last 10 lines of watchdog_auto.log:"
tail -10 watchdog_auto.log 2>/dev/null || echo "No log file yet."
echo ""
echo "Current Alerts:"
grep -c "severity.*WARN\|severity.*CRITICAL" watchdog_output.jsonl 2>/dev/null || echo "0"
