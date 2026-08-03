#!/usr/bin/env python3
"""
Watchdog — Module 34: QPU Calibration Drift Detector
Monitors IBM Quantum backend calibration frequency via Qiskit Runtime API.
Anomalous calibration cycles (too frequent, mid-job) indicate:
  - Hardware tampering
  - Denial of service on the QPU
  - Control system instability

Requires: qiskit-ibm-runtime (pip install qiskit-ibm-runtime)
Credentials: IBM_QUANTUM_TOKEN env var
Falls back to status-only logging if not configured.
"""
import json, datetime, os, time
from collections import deque

CALIBRATION_HISTORY_FILE = "/tmp/watchdog_qpu_calibration.json"
CALIBRATION_SPIKE_WINDOW = 600    # seconds — 10 minutes
CALIBRATION_SPIKE_COUNT  = 3      # >3 calibrations in window = anomalous
T1_DROP_THRESHOLD        = 0.50   # 50% drop in T1 = critical
T2_DROP_THRESHOLD        = 0.50   # 50% drop in T2 = critical
POLL_INTERVAL            = 300    # seconds between checks (5 min)

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_history() -> dict:
    try:
        with open(CALIBRATION_HISTORY_FILE) as f:
            return json.load(f)
    except:
        return {"calibration_times": [], "t1_baseline": {}, "t2_baseline": {}}

def save_history(h: dict):
    try:
        with open(CALIBRATION_HISTORY_FILE, "w") as f:
            json.dump(h, f)
    except:
        pass

def fetch_backend_properties(token: str, backend_name: str = None) -> dict | None:
    """
    Fetch real backend.properties() from IBM Quantum via Qiskit Runtime.
    Returns dict with last_update_date, per-qubit T1/T2, gate errors.
    """
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        svc = QiskitRuntimeService(token=token)

        if backend_name:
            backend = svc.backend(backend_name)
        else:
            backend = svc.least_busy(operational=True, simulator=False,
                                      min_num_qubits=5)

        props = backend.properties(refresh=True)
        if props is None:
            return None

        # Extract per-qubit T1, T2
        qubit_data = {}
        for i in range(backend.num_qubits):
            try:
                t1 = props.t1(i)
                t2 = props.t2(i)
                qubit_data[str(i)] = {
                    "t1_s": t1,
                    "t2_s": t2,
                    "readout_error": props.readout_error(i)
                }
            except:
                pass

        # Gate errors for 2-qubit gates
        gate_errors = {}
        try:
            for gate in props.gates:
                if len(gate.qubits) == 2:
                    key = f"{gate.gate}_{gate.qubits[0]}_{gate.qubits[1]}"
                    for param in gate.parameters:
                        if param.name == "gate_error":
                            gate_errors[key] = param.value
        except:
            pass

        return {
            "backend":          backend.name,
            "last_update":      props.last_update_date.isoformat() if props.last_update_date else None,
            "num_qubits":       backend.num_qubits,
            "qubit_properties": qubit_data,
            "gate_errors":      gate_errors,
        }

    except ImportError:
        return {"error": "qiskit_ibm_runtime not installed"}
    except Exception as e:
        return {"error": str(e)}

def check_calibration_frequency(history: dict, new_timestamp: str) -> list:
    """Check if calibration is happening too frequently."""
    alerts = []
    times = history.get("calibration_times", [])
    now_ts = datetime.datetime.fromisoformat(new_timestamp).timestamp()

    # Count calibrations in the last CALIBRATION_SPIKE_WINDOW seconds
    recent = [t for t in times if now_ts - t < CALIBRATION_SPIKE_WINDOW]
    if len(recent) >= CALIBRATION_SPIKE_COUNT:
        alerts.append({
            "event":    "CALIBRATION_FREQUENCY_SPIKE",
            "severity": "WARN",
            "count":    len(recent),
            "window_s": CALIBRATION_SPIKE_WINDOW,
            "note":     "Unusually frequent QPU recalibration — possible hardware instability or DoS"
        })
    return alerts

def check_coherence_degradation(history: dict, current: dict) -> list:
    """Compare current T1/T2 against stored baseline. Flag >50% drops."""
    alerts = []
    t1_base = history.get("t1_baseline", {})
    t2_base = history.get("t2_baseline", {})
    qubit_data = current.get("qubit_properties", {})

    degraded_t1, degraded_t2 = [], []

    for qubit_id, props in qubit_data.items():
        t1 = props.get("t1_s")
        t2 = props.get("t2_s")

        if t1 and qubit_id in t1_base and t1_base[qubit_id] > 0:
            drop = (t1_base[qubit_id] - t1) / t1_base[qubit_id]
            if drop > T1_DROP_THRESHOLD:
                degraded_t1.append({"qubit": qubit_id,
                                     "baseline_us": round(t1_base[qubit_id]*1e6, 2),
                                     "current_us":  round(t1*1e6, 2),
                                     "drop_pct":    round(drop*100, 1)})

        if t2 and qubit_id in t2_base and t2_base[qubit_id] > 0:
            drop = (t2_base[qubit_id] - t2) / t2_base[qubit_id]
            if drop > T2_DROP_THRESHOLD:
                degraded_t2.append({"qubit": qubit_id,
                                     "baseline_us": round(t2_base[qubit_id]*1e6, 2),
                                     "current_us":  round(t2*1e6, 2),
                                     "drop_pct":    round(drop*100, 1)})

    if len(degraded_t1) >= 3:
        alerts.append({"event":    "T1_COHERENCE_DEGRADATION",
                        "severity": "CRITICAL",
                        "qubits":   degraded_t1,
                        "note":     "Multiple qubits T1 dropped >50% — consistent with thermal or EM attack"})

    if len(degraded_t2) >= 3:
        alerts.append({"event":    "T2_COHERENCE_DEGRADATION",
                        "severity": "CRITICAL",
                        "qubits":   degraded_t2,
                        "note":     "Multiple qubits T2 dropped >50% — phase decoherence anomaly"})

    return alerts

def main():
    token   = os.environ.get("IBM_QUANTUM_TOKEN")
    backend = os.environ.get("IBM_QUANTUM_BACKEND")   # optional — uses least_busy if unset
    log     = open(f"module34_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "34_qpu_calibration_drift",
          "credentials": "present" if token else "absent"})

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set IBM_QUANTUM_TOKEN env var to enable live calibration monitoring"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    history = load_history()
    alerts  = 0

    while True:
        props = fetch_backend_properties(token, backend)
        if not props or "error" in props:
            emit({"event": "FETCH_ERROR", "detail": props})
        else:
            emit({"event": "CALIBRATION_SNAPSHOT", **props})
            now_ts = time.time()

            # Track calibration timestamp
            if props.get("last_update"):
                history["calibration_times"].append(now_ts)
                history["calibration_times"] = history["calibration_times"][-100:]

            # Check frequency
            for alert in check_calibration_frequency(history, now_iso()):
                alerts += 1
                emit(alert)

            # Check coherence degradation
            for alert in check_coherence_degradation(history, props):
                alerts += 1
                emit(alert)

            # Update baselines if first run
            if not history["t1_baseline"]:
                history["t1_baseline"] = {k: v.get("t1_s", 0)
                                            for k, v in props.get("qubit_properties", {}).items()}
                history["t2_baseline"] = {k: v.get("t2_s", 0)
                                            for k, v in props.get("qubit_properties", {}).items()}
                emit({"event": "BASELINE_ESTABLISHED",
                      "backend": props.get("backend"),
                      "num_qubits": props.get("num_qubits")})

            save_history(history)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
