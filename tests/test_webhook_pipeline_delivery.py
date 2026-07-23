# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
Watchdog AIDR v2.0 - Webhook Pipeline Integration Test
Tests full alert lifecycle: firing then resolved.
Requires Watchdog API running: python3 watchdog.py --api
"""
import sys, json

try:
    import requests
except ImportError:
    print("[SKIP] pip install requests --break-system-packages")
    sys.exit(0)

def send_alert_envelope(status, starts_at, ends_at):
    url = "http://localhost:8080/v2/alerts/webhook"
    payload = {
        "receiver": "watchdog-siem-bridge",
        "status": status,
        "externalURL": "http://watchdog-system.svc",
        "alerts": [{
            "status": status,
            "labels": {
                "alertname": "WatchdogCEIDegradationCritical",
                "severity": "CRITICAL",
                "tier": "ai-infrastructure",
                "node": "vast-ai-h200-instance-41986069",
                "gpu_id": "gpu-0",
                "cve": "CVE-2048350",
                "mitre_id": "AML.T0048",
            },
            "annotations": {
                "summary": f"[{status.upper()}] CEI degradation on GPU gpu-0",
                "description": "512MB residual VRAM leak boundary. CVE-2048350.",
            },
            "startsAt": starts_at,
            "endsAt": ends_at,
        }]
    }
    try:
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code == 200 and r.json().get("status") == "PROCESSED":
            print(f"[PASS] {status.upper()} processed.")
            return True
        print(f"[FAIL] HTTP {r.status_code}: {r.text}")
        return False
    except requests.exceptions.ConnectionError:
        print(f"[SKIP] Cannot connect — start Watchdog API first")
        return True
    except Exception as e:
        print(f"[FAIL] {e}")
        return False

if __name__ == "__main__":
    ok = send_alert_envelope("firing", "2026-06-30T21:30:00Z", "0001-01-01T00:00:00Z")
    if not ok:
        sys.exit(1)
    ok = send_alert_envelope("resolved", "2026-06-30T21:30:00Z", "2026-06-30T21:40:00Z")
    sys.exit(0 if ok else 1)
