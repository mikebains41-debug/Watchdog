#!/usr/bin/env python3
"""
Watchdog — Module 46: D-Wave Annealer Side-Channel Detection
Refactored to use quantum_providers abstraction layer.
"""
import json, os, sys, random, statistics
from datetime import datetime, timezone
from typing import Dict, List, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from quantum_providers import get_provider

CV_THRESHOLD = 0.15
AUTOCORR_THRESHOLD = 0.50
ROLLING_WINDOW = 20
STATE_PATH = os.path.expanduser("~/watchdog_qc_anneal_state.json")


def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_PATH):
        return {"timings": []}
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"timings": []}


def save_state(state: Dict[str, Any]) -> None:
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, default=str)


def emit(event_type: str, details: Dict[str, Any]) -> None:
    print(json.dumps({
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **details
    }))


def lag1_autocorr(series: List[float]) -> float:
    if len(series) < 2:
        return 0.0
    mean = statistics.mean(series)
    num = sum((series[i] - mean) * (series[i+1] - mean) for i in range(len(series)-1))
    den = sum((x - mean) ** 2 for x in series)
    return num / den if den != 0 else 0.0


def coefficient_of_variation(series: List[float]) -> float:
    if len(series) < 2 or statistics.mean(series) == 0:
        return 1.0
    return statistics.stdev(series) / statistics.mean(series)


def main():
    provider = get_provider()
    print(f"[module46] Using provider: {provider.provider_name}", file=sys.stderr)

    try:
        jobs = provider.get_job_history(limit=50)
    except Exception as e:
        emit("ANNEALER_DATA_FETCH_FAILED", {"error": str(e)})
        sys.exit(0)

    timings = []
    for job in jobs:
        try:
            timing = provider.get_job_timing(job.job_id)
            val = timing.get("anneal_seconds") or timing.get("exec_seconds")
            if val is not None and val > 0:
                timings.append(val)
        except Exception:
            continue

    state = load_state()
    state["timings"].extend(timings)
    state["timings"] = state["timings"][-ROLLING_WINDOW:]

    if len(state["timings"]) < ROLLING_WINDOW:
        emit("ANNEALER_INSUFFICIENT_DATA", {
            "samples": len(state["timings"]),
            "need": ROLLING_WINDOW,
        })
        save_state(state)
        return

    cv = coefficient_of_variation(state["timings"])
    ac = lag1_autocorr(state["timings"])

    if cv < CV_THRESHOLD and ac > AUTOCORR_THRESHOLD:
        emit("ANNEALER_SIDECHANNEL_DETECTED", {
            "severity": "WARN",
            "confidence": 0.75,
            "cv": round(cv, 4),
            "lag1_autocorr": round(ac, 4),
            "window": ROLLING_WINDOW,
        })

        # Active response: inject noise job
        try:
            noise = {
                "type": "ising",
                "linear": {i: random.choice([-1, 1]) for i in range(4)},
                "quadratic": {(i, j): random.choice([-1, 1]) for i in range(4) for j in range(i+1, 4)},
                "annealing_time_us": random.randint(20, 200),
            }
            device = provider.list_devices()[0]
            noise_job = provider.submit_circuit(noise, shots=1, backend=device)
            emit("NOISE_JOB_INJECTED", {"noise_job_id": noise_job})
        except Exception as e:
            emit("NOISE_JOB_FAILED", {"error": str(e)})
    else:
        emit("ANNEALER_TIMING_NORMAL", {
            "cv": round(cv, 4),
            "lag1_autocorr": round(ac, 4),
            "window": ROLLING_WINDOW,
        })

    save_state(state)


if __name__ == "__main__":
    main()
