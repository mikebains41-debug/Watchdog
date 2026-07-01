"""
Watchdog AIDR v2.0 - Prometheus Metrics Scraper and Alert Tester
Queries Watchdog /metrics endpoint and evaluates whether current
telemetry would trigger PrometheusRule alert conditions.
Run Watchdog first: python3 watchdog.py --api
Then: python3 tests/test_metrics_alert_firing.py
"""
import sys

try:
    import requests
except ImportError:
    print("[SKIP] pip install requests --break-system-packages")
    sys.exit(0)

class PrometheusMetricsTester:
    def __init__(self, endpoint_url="http://localhost:8080/metrics"):
        self.endpoint_url = endpoint_url

    def sample_and_evaluate(self):
        print(f"[TESTING] Fetching metrics from {self.endpoint_url}")
        try:
            r = requests.get(self.endpoint_url, timeout=5)
            if r.status_code != 200:
                return {"status": "FAIL", "reason": f"HTTP {r.status_code}"}
            return self._parse_and_validate(r.text)
        except requests.exceptions.ConnectionError:
            print("[SKIP] Start Watchdog API first: python3 watchdog.py --api")
            return {"status": "SKIP"}
        except Exception as e:
            return {"status": "FAIL", "reason": str(e)}

    def _parse_and_validate(self, raw_text):
        power = util = memory = None
        for line in raw_text.splitlines():
            if line.startswith("#"): continue
            if "watchdog_gpu_power_watts" in line:
                try: power = float(line.split()[-1])
                except: pass
            elif "watchdog_gpu_util_pct" in line:
                try: util = float(line.split()[-1])
                except: pass
            elif "watchdog_gpu_memory_used_mb" in line:
                try: memory = float(line.split()[-1])
                except: pass
        print(f"[METRICS] power={power}W util={util}% memory={memory}MB")
        firing = []
        if power and util is not None:
            if power > 88 and util == 0:
                firing.append("WatchdogGhostPowerDetected")
                print("[ALERT] WatchdogGhostPowerDetected — CVE-2048350")
            if power > 400 and util < 20:
                firing.append("WatchdogCEIDegradationCritical")
                print("[ALERT] WatchdogCEIDegradationCritical")
        if memory and util is not None:
            if memory > 100 and util == 0:
                firing.append("WatchdogVRAMResidualExposure")
                print("[ALERT] WatchdogVRAMResidualExposure — CVE-2048350")
        if not firing:
            print("[NOMINAL] All metrics within healthy bounds.")
        return {"status": "FIRING" if firing else "NOMINAL", "alerts": firing}

if __name__ == "__main__":
    PrometheusMetricsTester().sample_and_evaluate()
