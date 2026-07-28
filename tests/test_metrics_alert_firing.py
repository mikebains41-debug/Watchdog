# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog v2.0 - Prometheus Metrics Endpoint Validation

FIXED vs. original:
  - The original independently reimplemented alert-firing logic with
    hardcoded thresholds (power>88W, power>400W, memory>100MB) that were
    completely disconnected from the real, learned-baseline detectors
    this repo actually runs. A GPU could be flagged "firing" by this
    script while the real GhostPowerDetector -- calibrated to that
    specific GPU's own baseline -- stays silent, or the reverse. Two
    different, disagreeing definitions of "alert" for the same system is
    worse than having one correct one.
  - Replaced with what this script can actually and honestly verify:
    that the /metrics endpoint is reachable, returns valid Prometheus
    exposition format, and exposes the metric names the pipeline is
    supposed to populate. It does NOT judge whether current values
    should be alerting -- that judgment belongs exclusively to the real
    detectors, not a second, independent copy of their logic.
  - Previously had 0 pytest-discoverable functions (none prefixed
    test_). The parsing logic is now factored into a standalone,
    importable function with real test_ coverage in
    tests/test_metrics_endpoint_validation.py, while this file keeps its
    original purpose as a live integration check you run by hand.

Run Watchdog first: python3 watchdog.py --api
Then: python3 tests/test_metrics_alert_firing.py
"""
import sys

try:
    import requests
except ImportError:
    print("[SKIP] pip install requests --break-system-packages")
    sys.exit(0)

# Always expected, regardless of whether any GPU telemetry has flowed in yet.
EXPECTED_METRICS = [
    'watchdog_alerts_total',
    'watchdog_gpu_count',
]

# These four only appear once _state['telemetry'] has at least one row --
# which requires watchdog.py's on_sample callback to call
# api.server.update_state(telemetry_row=row). As of tonight that wiring
# does not exist yet (a separate, known, larger gap -- see the comment in
# api/server.py above _pipeline). Their absence here is expected, not a
# failure of this endpoint.
TELEMETRY_DEPENDENT_METRICS = [
    'watchdog_gpu_power_watts',
    'watchdog_gpu_memory_used_mb',
    'watchdog_gpu_temp_celsius',
    'watchdog_gpu_util_pct',
]


def validate_metrics_text(raw_text):
    """
    Pure parsing/validation logic, deliberately factored out so it can
    be unit-tested against synthetic Prometheus text without a live
    server. Checks: every non-comment line parses as valid Prometheus
    exposition format (a metric name, optional {labels}, and a numeric
    value), and the always-expected metric names are present.

    Does not, and should not, judge whether any value should be
    "firing" -- see module docstring for why that logic was removed.
    """
    lines = raw_text.splitlines()
    metric_names_seen = set()
    malformed = []
    for line in lines:
        if not line.strip() or line.startswith('#'):
            continue
        name_part = line.split('{')[0].split(' ')[0]
        if name_part:
            metric_names_seen.add(name_part)
        parts = line.rsplit(' ', 1)
        if len(parts) != 2:
            malformed.append(line)
            continue
        try:
            float(parts[1])
        except ValueError:
            malformed.append(line)

    missing_required = [m for m in EXPECTED_METRICS if m not in metric_names_seen]
    missing_telemetry = [m for m in TELEMETRY_DEPENDENT_METRICS if m not in metric_names_seen]

    ok = not malformed and not missing_required
    return {
        "status": "PASS" if ok else "FAIL",
        "metric_names_seen": sorted(metric_names_seen),
        "malformed_lines": malformed,
        "missing_required": missing_required,
        "missing_telemetry_dependent": missing_telemetry,
    }


class PrometheusMetricsValidator:
    def __init__(self, endpoint_url="http://localhost:8080/metrics"):
        self.endpoint_url = endpoint_url

    def validate(self):
        print(f"[TESTING] Fetching metrics from {self.endpoint_url}")
        try:
            r = requests.get(self.endpoint_url, timeout=5)
        except requests.exceptions.ConnectionError:
            print("[SKIP] Start Watchdog API first: python3 watchdog.py --api")
            return {"status": "SKIP"}
        except Exception as e:
            return {"status": "FAIL", "reason": str(e)}

        if r.status_code != 200:
            return {"status": "FAIL", "reason": f"HTTP {r.status_code}"}

        result = validate_metrics_text(r.text)
        print(f"[METRICS] {len(result['metric_names_seen'])} distinct metric names found")
        if result["malformed_lines"]:
            print(f"[FAIL] {len(result['malformed_lines'])} malformed line(s), "
                  f"e.g.: {result['malformed_lines'][0]!r}")
        if result["missing_required"]:
            print(f"[FAIL] Missing always-expected metrics: {result['missing_required']}")
        if result["missing_telemetry_dependent"]:
            print(f"[INFO] Telemetry-dependent metrics not present: "
                  f"{result['missing_telemetry_dependent']} -- expected until "
                  f"watchdog.py calls update_state(telemetry_row=...), a "
                  f"separate known gap, not a failure of this endpoint")
        return result


if __name__ == "__main__":
    result = PrometheusMetricsValidator().validate()
    print(f"[RESULT] {result['status']}")
    if result["status"] == "FAIL":
        sys.exit(1)
