#!/usr/bin/env python3
"""
Watchdog — Module 50: Quantum Load Balancer Manipulation Detector
Monitors multi-fridge qubit allocation for anomalous routing decisions.
An attacker manipulating the load balancer can:
  - Route all jobs to a single QPU to exhaust calibration budget
  - Force jobs onto degraded qubits to increase error rates
  - Create hotspots that accelerate hardware wear

Integrates with: quantum_models/M_super_fridge_load_balancer.py
Requires: IBM_QUANTUM_TOKEN env var for live queue data
"""
import json, datetime, os, sys, time, math
from collections import defaultdict, deque

# ── Quantum models path ───────────────────────────────────────────────
_QM_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         '..', 'quantum_models')
if os.path.isdir(_QM_PATH):
    sys.path.insert(0, _QM_PATH)

try:
    from M_super_fridge_load_balancer import SuperFridgeLoadBalancer
    LB_AVAILABLE = True
except ImportError:
    LB_AVAILABLE = False

HOTSPOT_THRESHOLD    = 0.70   # one backend gets >70% of jobs = hotspot
BASELINE_SAMPLES     = 10     # polls before baseline
POLL_INTERVAL        = 300    # seconds between checks
LB_LOG_FILE          = "/tmp/watchdog_lb_distribution.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_lb_log() -> dict:
    try:
        with open(LB_LOG_FILE) as f:
            return json.load(f)
    except:
        return {"distributions": [], "backend_counts": {}, "sample_count": 0}

def save_lb_log(log: dict):
    try:
        with open(LB_LOG_FILE, "w") as f:
            json.dump(log, f)
    except:
        pass

def get_queue_distribution(token: str | None) -> dict | None:
    """
    Get current job queue distribution across available backends.
    Returns dict of backend_name -> pending_job_count.
    """
    if not token:
        return None

    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        svc      = QiskitRuntimeService(token=token)
        backends = svc.backends(operational=True, simulator=False)

        distribution = {}
        for backend in backends[:10]:   # Check up to 10 backends
            try:
                status = backend.status()
                distribution[backend.name] = {
                    "pending_jobs": status.pending_jobs,
                    "operational":  status.operational,
                    "n_qubits":     backend.num_qubits,
                }
            except:
                pass
        return distribution
    except ImportError:
        return None
    except Exception as e:
        return {"error": str(e)}

def get_lb_recommendation(distribution: dict) -> dict | None:
    """
    Ask M_super_fridge_load_balancer for optimal allocation.
    Compare against actual distribution to detect manipulation.
    """
    if not LB_AVAILABLE or not distribution:
        return None

    try:
        lb = SuperFridgeLoadBalancer()
        # Build fridge list from backends
        fridges = []
        for name, info in distribution.items():
            if isinstance(info, dict) and "n_qubits" in info:
                fridges.append({
                    "name":    name,
                    "qubits":  info["n_qubits"],
                    "pending": info.get("pending_jobs", 0),
                })

        if hasattr(lb, 'recommend') and fridges:
            recommendation = lb.recommend(fridges)
            return recommendation
        elif hasattr(lb, 'optimal_allocation') and fridges:
            recommendation = lb.optimal_allocation(fridges)
            return recommendation
    except:
        pass
    return None

def detect_hotspot(distribution: dict) -> list:
    """Detect if one backend is getting a disproportionate share of jobs."""
    alerts = []
    if not distribution or "error" in distribution:
        return alerts

    # Filter to backends with actual pending jobs
    counts = {k: v.get("pending_jobs", 0) for k, v in distribution.items()
              if isinstance(v, dict)}
    total  = sum(counts.values())

    if total < 5:
        return alerts   # Not enough jobs to analyse

    for backend, count in counts.items():
        share = count / total
        if share > HOTSPOT_THRESHOLD:
            alerts.append({
                "event":    "LOAD_BALANCER_HOTSPOT",
                "severity": "WARN",
                "backend":  backend,
                "share_pct": round(share * 100, 1),
                "pending_jobs": count,
                "total_jobs":   total,
                "threshold_pct": HOTSPOT_THRESHOLD * 100,
                "confidence": 0.65,
                "note":     (f"{backend} receiving {round(share*100,1)}% of all jobs — "
                             "possible load balancer manipulation or DDoS routing"),
                "model":    "M_super_fridge_load_balancer"
            })

    return alerts

def detect_degraded_routing(distribution: dict, lb_recommendation: dict | None) -> list:
    """
    Compare actual distribution against model-recommended optimal allocation.
    Significant deviation may indicate manipulated routing.
    """
    alerts = []
    if not lb_recommendation or not distribution:
        return alerts

    try:
        # If recommendation has a preferred backend, check if jobs are being
        # routed away from it (forcing jobs onto degraded hardware)
        recommended = lb_recommendation.get("recommended_backend") or \
                      lb_recommendation.get("optimal") or \
                      lb_recommendation.get("backend")

        if recommended and isinstance(distribution, dict):
            rec_count   = distribution.get(recommended, {})
            rec_pending = rec_count.get("pending_jobs", 0) if isinstance(rec_count, dict) else 0
            total       = sum(v.get("pending_jobs", 0) for v in distribution.values()
                              if isinstance(v, dict))

            if total > 10 and rec_pending / total < 0.10:
                alerts.append({
                    "event":       "LOAD_BALANCER_DEVIATION",
                    "severity":    "INFO",
                    "recommended": recommended,
                    "actual_share_pct": round(rec_pending / total * 100, 1),
                    "confidence":  0.50,
                    "note":        (f"Model recommends {recommended} but it's receiving <10% of jobs — "
                                   "verify load balancer config"),
                    "model":       "M_super_fridge_load_balancer"
                })
    except:
        pass

    return alerts

def main():
    token = os.environ.get("IBM_QUANTUM_TOKEN")
    log   = open(f"module50_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "50_load_balancer_guard",
          "lb_model": "M_super_fridge_load_balancer",
          "lb_available": LB_AVAILABLE,
          "hotspot_threshold_pct": HOTSPOT_THRESHOLD * 100,
          "credentials": "present" if token else "absent"})

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set IBM_QUANTUM_TOKEN to enable live queue distribution monitoring"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    lb_log  = load_lb_log()
    alerts  = 0

    while True:
        distribution = get_queue_distribution(token)

        if distribution and "error" not in distribution:
            emit({"event": "QUEUE_DISTRIBUTION", "backends": len(distribution)})

            # Hotspot detection
            for alert in detect_hotspot(distribution):
                alerts += 1
                emit(alert)

            # Load balancer model comparison
            lb_rec = get_lb_recommendation(distribution)
            if lb_rec:
                emit({"event": "LB_RECOMMENDATION", "recommendation": str(lb_rec)})
                for alert in detect_degraded_routing(distribution, lb_rec):
                    emit(alert)

            lb_log["sample_count"] = lb_log.get("sample_count", 0) + 1
            save_lb_log(lb_log)

        elif distribution and "error" in distribution:
            emit({"event": "FETCH_ERROR", "detail": distribution.get("error")})

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
