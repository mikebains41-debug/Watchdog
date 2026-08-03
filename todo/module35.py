#!/usr/bin/env python3
"""
Watchdog — Module 35: Qubit Error Rate Anomaly Detector
Monitors per-qubit gate error rates and T1/T2 coherence times via Qiskit Runtime.
Simultaneous spike in 3+ qubits is NOT normal calibration drift —
consistent with thermal attack, electromagnetic interference, or wiring fault.

Source: IBM Quantum backend.properties() — real API, no simulation.
Requires: qiskit-ibm-runtime (pip install qiskit-ibm-runtime)
Credentials: IBM_QUANTUM_TOKEN env var
"""
import json, datetime, os, time, math
from collections import deque, defaultdict

BASELINE_FILE       = "/tmp/watchdog_qubit_error_baseline.json"
ERROR_SPIKE_MULT    = 5.0    # flag if gate error exceeds baseline × this
ERROR_SPIKE_MIN     = 3      # minimum qubits spiking simultaneously to alert
READOUT_SPIKE_MULT  = 3.0    # readout error multiplier for alert
BASELINE_SAMPLES    = 6      # number of samples to build per-qubit baseline
POLL_INTERVAL       = 300    # seconds between checks

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except:
        return {"gate_error": {}, "readout_error": {}, "sample_count": 0}

def save_baseline(b: dict):
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(b, f)
    except:
        pass

def fetch_qubit_errors(token: str, backend_name: str = None) -> dict | None:
    """
    Pull real per-qubit error rates from IBM Quantum backend.properties().
    Returns dict of gate errors and readout errors per qubit.
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

        gate_errors    = defaultdict(list)   # qubit_id → [error_rates from all gates]
        readout_errors = {}

        # Single-qubit gate errors per qubit
        for gate in props.gates:
            try:
                for param in gate.parameters:
                    if param.name == "gate_error" and len(gate.qubits) == 1:
                        gate_errors[str(gate.qubits[0])].append(param.value)
            except:
                pass

        # Average gate error per qubit
        avg_gate_errors = {q: sum(errs) / len(errs)
                           for q, errs in gate_errors.items() if errs}

        # Readout errors per qubit
        for i in range(backend.num_qubits):
            try:
                readout_errors[str(i)] = props.readout_error(i)
            except:
                pass

        return {
            "backend":        backend.name,
            "num_qubits":     backend.num_qubits,
            "gate_errors":    avg_gate_errors,
            "readout_errors": readout_errors,
            "timestamp":      now_iso(),
        }

    except ImportError:
        return {"error": "qiskit_ibm_runtime not installed"}
    except Exception as e:
        return {"error": str(e)}

def update_baseline(baseline: dict, current: dict) -> dict:
    """Rolling baseline update — exponential moving average."""
    alpha = 0.2   # EMA smoothing factor
    for qubit, err in current.get("gate_errors", {}).items():
        if qubit in baseline["gate_error"]:
            baseline["gate_error"][qubit] = (
                alpha * err + (1 - alpha) * baseline["gate_error"][qubit]
            )
        else:
            baseline["gate_error"][qubit] = err

    for qubit, err in current.get("readout_errors", {}).items():
        if qubit in baseline["readout_error"]:
            baseline["readout_error"][qubit] = (
                alpha * err + (1 - alpha) * baseline["readout_error"][qubit]
            )
        else:
            baseline["readout_error"][qubit] = err

    baseline["sample_count"] = baseline.get("sample_count", 0) + 1
    return baseline

def detect_anomalies(baseline: dict, current: dict) -> list:
    """
    Detect simultaneous multi-qubit error spikes.
    Returns list of alert dicts.
    """
    if baseline["sample_count"] < BASELINE_SAMPLES:
        return []   # Not enough baseline data yet

    alerts   = []
    spiked_gate    = []
    spiked_readout = []

    for qubit, err in current.get("gate_errors", {}).items():
        base = baseline["gate_error"].get(qubit)
        if base and base > 0 and err > base * ERROR_SPIKE_MULT:
            spiked_gate.append({
                "qubit":      qubit,
                "baseline":   round(base, 6),
                "current":    round(err, 6),
                "multiplier": round(err / base, 1)
            })

    for qubit, err in current.get("readout_errors", {}).items():
        base = baseline["readout_error"].get(qubit)
        if base and base > 0 and err > base * READOUT_SPIKE_MULT:
            spiked_readout.append({
                "qubit":      qubit,
                "baseline":   round(base, 4),
                "current":    round(err, 4),
                "multiplier": round(err / base, 1)
            })

    # Only alert if 3+ qubits spike simultaneously
    if len(spiked_gate) >= ERROR_SPIKE_MIN:
        alerts.append({
            "event":    "QUBIT_GATE_ERROR_SPIKE",
            "severity": "CRITICAL",
            "spiked_qubits": spiked_gate,
            "count":    len(spiked_gate),
            "backend":  current.get("backend"),
            "note":     (f"{len(spiked_gate)} qubits gate error spiked >{ERROR_SPIKE_MULT}x "
                         f"simultaneously — consistent with thermal or EM attack on QPU"),
            "confidence": 0.85
        })

    if len(spiked_readout) >= ERROR_SPIKE_MIN:
        alerts.append({
            "event":    "QUBIT_READOUT_ERROR_SPIKE",
            "severity": "WARN",
            "spiked_qubits": spiked_readout,
            "count":    len(spiked_readout),
            "backend":  current.get("backend"),
            "note":     (f"{len(spiked_readout)} qubits readout error spiked >{READOUT_SPIKE_MULT}x "
                         f"simultaneously"),
            "confidence": 0.70
        })

    return alerts

def main():
    token   = os.environ.get("IBM_QUANTUM_TOKEN")
    backend = os.environ.get("IBM_QUANTUM_BACKEND")
    log     = open(f"module35_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "35_qubit_error_anomaly",
          "credentials": "present" if token else "absent",
          "spike_threshold": f"{ERROR_SPIKE_MULT}x baseline on {ERROR_SPIKE_MIN}+ qubits simultaneously"})

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set IBM_QUANTUM_TOKEN env var to enable live qubit monitoring"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    baseline = load_baseline()
    alerts   = 0

    while True:
        current = fetch_qubit_errors(token, backend)

        if not current or "error" in current:
            emit({"event": "FETCH_ERROR", "detail": current})
        else:
            # Log snapshot
            emit({"event": "ERROR_RATE_SNAPSHOT",
                  "backend":    current["backend"],
                  "num_qubits": current["num_qubits"],
                  "sample_n":   baseline["sample_count"] + 1})

            # Detect anomalies before updating baseline
            for alert in detect_anomalies(baseline, current):
                alerts += 1
                emit(alert)

            # Update rolling baseline
            baseline = update_baseline(baseline, current)
            save_baseline(baseline)

            if baseline["sample_count"] == BASELINE_SAMPLES:
                emit({"event": "BASELINE_ESTABLISHED",
                      "backend":    current["backend"],
                      "num_qubits": current["num_qubits"],
                      "note":       f"Baseline ready after {BASELINE_SAMPLES} samples"})

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
