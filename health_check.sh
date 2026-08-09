#!/bin/bash
echo "Running health check..."
cd "$(dirname "$0")"
python3 run_all.py > ~/watchdog_health.log 2>&1

# Extract alerts count from output
ALERTS=$(grep "Alerts:" ~/watchdog_health.log | awk '{print $2}' | head -1)
if [ -z "$ALERTS" ]; then
    ALERTS=0
fi

if [ "$ALERTS" -gt 0 ]; then
    echo "⚠️  $ALERTS alert(s) found. Notifying..."
    ./scripts/notify.sh "Watchdog found $ALERTS alerts. Check dashboard."
fi

if grep -q "MODULE_ERROR\|RUNNER_ERROR" ~/watchdog_health.log; then
    echo "❌ Some modules failed. Check ~/watchdog_health.log"
    grep -E "MODULE_ERROR|RUNNER_ERROR" ~/watchdog_health.log
    exit 1
else
    echo "✅ All modules passed health check."
    echo "Summary:"
    tail -10 ~/watchdog_health.log
    exit 0
fi
