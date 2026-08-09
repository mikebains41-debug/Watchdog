#!/usr/bin/env bash
set -e

SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
EMAIL_RECIPIENT="${EMAIL_RECIPIENT:-}"
EMAIL_SENDER="${EMAIL_SENDER:-watchdog@localhost}"
HOSTNAME="$(hostname 2>/dev/null || echo "unknown")"
TIMESTAMP="$(date -Iseconds)"

SUBJECT="Watchdog Quantum Alert – $HOSTNAME"
MESSAGE="$1"

if [ -z "$MESSAGE" ]; then
    echo "Usage: $0 <message>"
    exit 1
fi

if [ -n "$SLACK_WEBHOOK_URL" ]; then
    PAYLOAD="{\"text\":\"*$SUBJECT*\n$MESSAGE\n\nTimestamp: $TIMESTAMP\"}"
    curl -s -X POST -H 'Content-type: application/json' --data "$PAYLOAD" "$SLACK_WEBHOOK_URL" > /dev/null
    echo "Slack notification sent."
else
    echo "SLACK_WEBHOOK_URL not set – skipping Slack."
fi

if [ -n "$EMAIL_RECIPIENT" ]; then
    MAIL_BODY="Subject: $SUBJECT\n\n$MESSAGE\n\nTimestamp: $TIMESTAMP\nHost: $HOSTNAME"
    if command -v sendmail >/dev/null 2>&1; then
        echo -e "$MAIL_BODY" | sendmail -f "$EMAIL_SENDER" "$EMAIL_RECIPIENT"
    elif command -v mail >/dev/null 2>&1; then
        echo -e "$MAIL_BODY" | mail -s "$SUBJECT" "$EMAIL_RECIPIENT"
    else
        echo "No mail command found – email skipped."
    fi
    echo "Email notification sent to $EMAIL_RECIPIENT."
else
    echo "EMAIL_RECIPIENT not set – skipping email."
fi

echo "Notification complete."
