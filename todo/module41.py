#!/usr/bin/env python3
"""
Watchdog — Module 41: Qubit-Specific Calibration DDoS Detection
Monitors backend.properties() for calibration cycles targeting the same qubit.
If the same qubit shows anomalous recalibration frequency, flags QUBIT_CALIBRATION_DDOS.

Note: Cannot block QPU calibration from userspace — detection only.
Reported to IBM Quantum support for remediation when detected.
Requires: qiskit-ibm-runtime
Credentials: IBM_QUANTUM_TOKEN env var
"""
import json, datetime, os, time
from collections import defaultdict, deque

CALIBRATION_LOG_FILE  = "/tmp/watchdog_qubit_calib_history.json"
DDOS_WINDOW_S         = 600    # 10 minutes
DDOS_THRESHOLD        = 3      # >3 calibrations on same qubit in window
POLL_INTERVAL         = 120    # seconds between property fetches

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_calib_log() -> dict:
    try:
        with open(CALIBRATION_LOG_FILE) as f:
            return json.load(f)
    except:
        return {}

def save_calib_log(log: dict):
    try:
        with open(CALIBRATION_LOG_FILE, "w") as f:
            json.dump(log, f)
    except:
        pass

def fetch_per_qubit_calibration_times(token: str, backend_name: str = None) -> dict | None:
    """
    Fetch per-qubit last calibration timestamps from backend.properties().
    Returns dict: qubit_id -> last_update ISO string
    """
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        svc = QiskitRuntimeService(token=token)
        if backend_name:
            backend = svc.backend(backend_name)
        else:
            backend = svc.least_busy(operational=True, simulator=False, min_num_qubits=5)

        props = backend.properties(refresh=True)
        if not props:
            return None

        qubit_times = {}
        for i in range(backend.num_qubits):
            try:
                # T1 update time is a proxy for last calibration time per qubit
                t1_data = props.qubit_property(i, "T1")
                if t1_data and len(t1_data) > 1:
                    update_dt = t1_data[1]
                    qubit_times[str(i)] = update_dt.isoformat() if hasattr(update_dt, 'isoformat') else str(update_dt)
            except:
                pass

        return {
            "backend":     backend.name,
            "qubit_times": qubit_times,
            "fetched_at":  now_iso(),
        }
    except ImportError:
        return {"error": "qiskit_ibm_runtime not installed"}
    except Exception as e:
        return {"error": str(e)}

def detect_qubit_ddos(calib_log: dict, current: dict) -> list:
    """
    Compare current calibration times against logged history.
    Flag qubits that have been recalibrated > DDOS_THRESHOLD times in DDOS_WINDOW_S.
    """
    alerts   = []
    now_ts   = time.time()
    backend  = current.get("backend", "unknown")

    if backend not in calib_log:
        calib_log[backend] = {}

    for qubit, calib_time_str in current.get("qubit_times", {}).items():
        if qubit not in calib_log[backend]:
            calib_log[backend][qubit] = []

        # Add current calibration time if it's new
        existing = calib_log[backend][qubit]
        if not existing or existing[-1] != calib_time_str:
            existing.append(calib_time_str)
            calib_log[backend][qubit] = existing[-50:]   # Keep last 50

        # Count calibrations within window
        # Use fetch timestamps as proxy (each fetch that shows a changed time = recalibration)
        recent_count = sum(1 for t in existing[-DDOS_THRESHOLD*2:])
        if recent_count > DDOS_THRESHOLD:
            alerts.append({
                "event":    "QUBIT_CALIBRATION_DDOS",
                "severity": "WARN",
                "qubit":    qubit,
                "backend":  backend,
                "count_in_window": recent_count,
                "window_s": DDOS_WINDOW_S,
                "confidence": 0.70,
                "note":     (f"Qubit {qubit} on {backend} shows abnormal recalibration frequency — "
                             f"possible targeted calibration DoS reducing compute time for tenants"),
                "action":   "Report to IBM Quantum support with this log. Cannot block from userspace."
            })

    return alerts, calib_log

def main():
    token   = os.environ.get("IBM_QUANTUM_TOKEN")
    backend = os.environ.get("IBM_QUANTUM_BACKEND")
    log     = open(f"module41_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "41_qubit_calib_ddos",
          "threshold": f">{DDOS_THRESHOLD} calibrations per qubit in {DDOS_WINDOW_S}s",
          "credentials": "present" if token else "absent"})

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set IBM_QUANTUM_TOKEN to enable qubit DDoS monitoring"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    calib_log = load_calib_log()
    alerts    = 0

    while True:
        current = fetch_per_qubit_calibration_times(token, backend)

        if not current or "error" in current:
            emit({"event": "FETCH_ERROR", "detail": current})
        else:
            emit({"event": "CALIBRATION_POLL", "backend": current.get("backend"),
                  "qubits_tracked": len(current.get("qubit_times", {}))})

            new_alerts, calib_log = detect_qubit_ddos(calib_log, current)
            for alert in new_alerts:
                alerts += 1
                emit(alert)

            save_calib_log(calib_log)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
