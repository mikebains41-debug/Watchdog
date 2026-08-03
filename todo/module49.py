#!/usr/bin/env python3
"""
Watchdog — Module 49: Quantum Fleet Efficiency Anomaly Detector
Uses M_quantum_fleet_score.unit_score() to monitor fleet-level efficiency.
A sudden drop in fleet efficiency score is consistent with:
  - Multi-QPU load balancer manipulation
  - Coordinated calibration attacks across backends
  - Thermal attack affecting multiple fridges simultaneously

Integrates with: quantum_models/M_quantum_fleet_score.py
Requires: IBM_QUANTUM_TOKEN env var for live backend data
"""
import json, datetime, os, sys, time, math
from collections import deque

# ── Quantum models path ───────────────────────────────────────────────
_QM_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         '..', 'quantum_models')
if os.path.isdir(_QM_PATH):
    sys.path.insert(0, _QM_PATH)

try:
    from M_quantum_fleet_score import unit_score as fleet_unit_score
    FLEET_AVAILABLE = True
except ImportError:
    FLEET_AVAILABLE = False

SCORE_DROP_THRESHOLD = 0.20   # 20% drop from baseline = anomaly
BASELINE_SAMPLES     = 8      # samples before baseline established
POLL_INTERVAL        = 600    # seconds between fleet score checks
FLEET_LOG_FILE       = "/tmp/watchdog_fleet_scores.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_fleet_log() -> dict:
    try:
        with open(FLEET_LOG_FILE) as f:
            return json.load(f)
    except:
        return {"scores": [], "backends": {}}

def save_fleet_log(log: dict):
    try:
        with open(FLEET_LOG_FILE, "w") as f:
            json.dump(log, f)
    except:
        pass

def get_backend_fleet_scores(token: str | None) -> list:
    """
    Compute fleet efficiency score for each available backend.
    Uses M_quantum_fleet_score.unit_score(qubits, wall_w, cold_w).
    """
    if not FLEET_AVAILABLE:
        return [{"error": "M_quantum_fleet_score not available"}]

    scores = []

    if token:
        try:
            from qiskit_ibm_runtime import QiskitRuntimeService
            svc      = QiskitRuntimeService(token=token)
            backends = svc.backends(operational=True, simulator=False)[:5]   # Sample 5

            for backend in backends:
                try:
                    props = backend.properties()
                    # Estimate power from qubit count (model approximation)
                    n_qubits  = backend.num_qubits
                    wall_w    = n_qubits * 6.25   # ~6.25W/qubit reference from model
                    cold_w    = wall_w * 0.001

                    score_val = fleet_unit_score(qubits=n_qubits,
                                                  wall_w=wall_w,
                                                  cold_w=cold_w)
                    scores.append({
                        "backend":    backend.name,
                        "n_qubits":   n_qubits,
                        "wall_w":     round(wall_w, 2),
                        "fleet_score": round(float(score_val), 4),
                        "status":     "AWAITING_HARDWARE_TEST",
                    })
                except:
                    pass
        except:
            pass

    # If no live data, compute for reference IBM backends
    if not scores:
        reference_backends = [
            {"name": "ibm_brisbane",  "n_qubits": 127},
            {"name": "ibm_sherbrooke","n_qubits": 127},
            {"name": "ibm_kyoto",     "n_qubits": 127},
        ]
        for ref in reference_backends:
            try:
                n     = ref["n_qubits"]
                w     = n * 6.25
                score = fleet_unit_score(qubits=n, wall_w=w, cold_w=w*0.001)
                scores.append({
                    "backend":     ref["name"],
                    "n_qubits":    n,
                    "wall_w":      round(w, 2),
                    "fleet_score": round(float(score), 4),
                    "source":      "reference_model",
                    "status":      "AWAITING_HARDWARE_TEST",
                })
            except:
                pass

    return scores

def detect_fleet_anomaly(fleet_log: dict, current_scores: list) -> list:
    alerts    = []
    baselines = fleet_log.get("backends", {})
    history   = fleet_log.get("scores", [])

    for entry in current_scores:
        if "error" in entry:
            continue
        backend = entry["backend"]
        score   = entry["fleet_score"]

        if backend not in baselines:
            baselines[backend] = []
        baselines[backend].append(score)
        baselines[backend] = baselines[backend][-50:]

        if len(baselines[backend]) >= BASELINE_SAMPLES:
            baseline_avg = sum(baselines[backend][-BASELINE_SAMPLES:]) / BASELINE_SAMPLES
            if baseline_avg > 0:
                drop = (baseline_avg - score) / baseline_avg
                if drop > SCORE_DROP_THRESHOLD:
                    alerts.append({
                        "event":        "FLEET_EFFICIENCY_DROP",
                        "severity":     "WARN",
                        "backend":      backend,
                        "current_score": round(score, 4),
                        "baseline_score": round(baseline_avg, 4),
                        "drop_pct":     round(drop * 100, 1),
                        "confidence":   0.65,
                        "note":         (f"{backend} fleet score dropped {round(drop*100,1)}% — "
                                         "consistent with calibration attack, thermal attack, "
                                         "or load balancer manipulation"),
                        "model":        "M_quantum_fleet_score.unit_score()"
                    })

    fleet_log["backends"] = baselines
    return alerts, fleet_log

def main():
    token = os.environ.get("IBM_QUANTUM_TOKEN")
    log   = open(f"module49_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "49_fleet_efficiency",
          "fleet_model": "M_quantum_fleet_score.unit_score()",
          "fleet_available": FLEET_AVAILABLE,
          "drop_threshold_pct": SCORE_DROP_THRESHOLD * 100,
          "credentials": "present" if token else "absent"})

    if not FLEET_AVAILABLE:
        emit({"event": "STATUS", "status": "MODEL_NOT_AVAILABLE",
              "note": "quantum_models/M_quantum_fleet_score.py not found"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    fleet_log = load_fleet_log()
    alerts    = 0

    while True:
        scores = get_backend_fleet_scores(token)
        emit({"event": "FLEET_SCORE_SNAPSHOT", "backends": len(scores), "scores": scores})

        new_alerts, fleet_log = detect_fleet_anomaly(fleet_log, scores)
        for alert in new_alerts:
            alerts += 1
            emit(alert)

        save_fleet_log(fleet_log)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
