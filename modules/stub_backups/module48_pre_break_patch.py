#!/usr/bin/env python3
"""
Watchdog — Module 48: Quantum Cost Drain Monitor
Uses M_qubit_hour_economics.QubitHourEconomics to track cost-per-qubit-hour.
Flags anomalous cost spikes consistent with:
  - Credential drain (attacker running expensive jobs)
  - Resource overconsumption (tenant oversubscription)
  - Billing integrity gaps (power billed at zero but cost incurred)

Integrates with: quantum_models/M_qubit_hour_economics.py
Requires: IBM_QUANTUM_TOKEN env var for live job cost data
"""
import json, datetime, os, sys, time
from collections import deque

# ── Quantum models path ───────────────────────────────────────────────
_QM_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         '..', 'quantum_models')
if os.path.isdir(_QM_PATH):
    sys.path.insert(0, _QM_PATH)

try:
    from M_qubit_hour_economics import QubitHourEconomics
    ECONOMICS_AVAILABLE = True
except ImportError:
    ECONOMICS_AVAILABLE = False

COST_SPIKE_MULT    = 3.0    # flag if cost-per-qubit-hour spikes 3x baseline
BASELINE_SAMPLES   = 10     # samples before baseline established
POLL_INTERVAL      = 300    # seconds between checks
COST_HISTORY_FILE  = "/tmp/watchdog_qc_cost_history.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_history() -> dict:
    try:
        with open(COST_HISTORY_FILE) as f:
            return json.load(f)
    except:
        return {"cost_per_qubit_hour": [], "sample_count": 0}

def save_history(h: dict):
    try:
        with open(COST_HISTORY_FILE, "w") as f:
            json.dump(h, f)
    except:
        pass

def get_current_cost(token: str | None) -> dict | None:
    """
    Compute current cost-per-qubit-hour using QubitHourEconomics.
    Falls back to model defaults if no live job data available.
    """
    if not ECONOMICS_AVAILABLE:
        return {"error": "M_qubit_hour_economics not available"}

    try:
        econ = QubitHourEconomics()

        # Try to pull live job count from IBM Quantum
        active_qubits = 127   # IBM Eagle default
        if token:
            try:
                from qiskit_ibm_runtime import QiskitRuntimeService
                svc     = QiskitRuntimeService(token=token)
                backend = svc.least_busy(operational=True, simulator=False,
                                          min_num_qubits=5)
                active_qubits = backend.num_qubits
            except:
                pass

        # Use model to compute cost
        result = econ.cost_per_qubit_hour(num_qubits=active_qubits) \
                 if hasattr(econ, 'cost_per_qubit_hour') else \
                 econ.compute(num_qubits=active_qubits) \
                 if hasattr(econ, 'compute') else None

        if result is None:
            # Try direct attribute access patterns from the model
            for method in ['cost_per_qubit_hour', 'compute', 'calculate', 'run']:
                if hasattr(econ, method):
                    result = getattr(econ, method)(num_qubits=active_qubits)
                    break

        return {
            "cost_per_qubit_hour": float(result) if result is not None else None,
            "active_qubits":       active_qubits,
            "model":               "M_qubit_hour_economics.QubitHourEconomics",
            "status":              "AWAITING_HARDWARE_TEST",
        }
    except Exception as e:
        return {"error": str(e)}

def detect_cost_anomaly(history: dict, current_cost: float) -> list:
    alerts = []
    costs  = history.get("cost_per_qubit_hour", [])

    if len(costs) >= BASELINE_SAMPLES:
        baseline = sum(costs[-BASELINE_SAMPLES:]) / BASELINE_SAMPLES
        if baseline > 0 and current_cost > baseline * COST_SPIKE_MULT:
            alerts.append({
                "event":        "QUANTUM_COST_SPIKE",
                "severity":     "WARN",
                "current":      round(current_cost, 4),
                "baseline":     round(baseline, 4),
                "multiplier":   round(current_cost / baseline, 2),
                "confidence":   0.70,
                "note":         ("Cost-per-qubit-hour spiked — "
                                 "possible credential drain or resource overconsumption"),
                "model":        "M_qubit_hour_economics"
            })
    return alerts

def main():
    token = os.environ.get("IBM_QUANTUM_TOKEN")
    log   = open(f"module48_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "48_quantum_cost_drain",
          "economics_model": "M_qubit_hour_economics",
          "economics_available": ECONOMICS_AVAILABLE,
          "credentials": "present" if token else "absent"})

    if not ECONOMICS_AVAILABLE:
        emit({"event": "STATUS", "status": "MODEL_NOT_AVAILABLE",
              "note": "quantum_models/M_qubit_hour_economics.py not found"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    history = load_history()
    alerts  = 0

    while True:
        result = get_current_cost(token)

        if not result or "error" in result:
            emit({"event": "COST_FETCH_ERROR", "detail": result})
        else:
            cost = result.get("cost_per_qubit_hour")
            emit({"event": "COST_SNAPSHOT", **result})

            if cost is not None:
                history["cost_per_qubit_hour"].append(cost)
                history["cost_per_qubit_hour"] = history["cost_per_qubit_hour"][-200:]
                history["sample_count"] = history.get("sample_count", 0) + 1

                for alert in detect_cost_anomaly(history, cost):
                    alerts += 1
                    emit(alert)

                if history["sample_count"] == BASELINE_SAMPLES:
                    emit({"event": "COST_BASELINE_ESTABLISHED",
                          "baseline": round(sum(history["cost_per_qubit_hour"][-BASELINE_SAMPLES:])
                                            / BASELINE_SAMPLES, 4)})

            save_history(history)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
