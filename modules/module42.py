#!/usr/bin/env python3
"""
Watchdog — Module 42: Job Queue Front-Running Detection
Finds: An attacker monitoring the public job queue to time a high-value job
       and infer its result from execution duration.

Refactored to use quantum_providers abstraction layer.
"""
import json, os, sys, statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from quantum_providers import get_provider, JobRecord

# ------------------------------------------------------------------ thresholds
DEVIATION_SIGMA = 1.5
BASELINE_MIN_JOBS = 5
ROLLING_WINDOW_JOBS = 20
STATE_PATH = os.path.expanduser("~/watchdog_qc_timing_state.json")
MAX_STATE_JOBS = 5000


def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_PATH):
        return {"seen_ids": [], "baselines": {}}
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"seen_ids": [], "baselines": {}}


def save_state(state: Dict[str, Any]) -> None:
    # Cap seen_ids to prevent unbounded growth
    if len(state.get("seen_ids", [])) > MAX_STATE_JOBS:
        state["seen_ids"] = state["seen_ids"][-MAX_STATE_JOBS:]
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, default=str)


def emit(event_type: str, details: Dict[str, Any]) -> None:
    print(json.dumps({
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **details
    }))


def compute_baseline(exec_times: List[float]) -> Optional[Dict[str, float]]:
    if len(exec_times) < BASELINE_MIN_JOBS:
        return None
    return {
        "mean": statistics.mean(exec_times),
        "std": statistics.pstdev(exec_times),  # population stddev
        "n": len(exec_times),
    }


def check_timing(job: JobRecord, baseline: Dict[str, float]) -> Optional[Dict[str, Any]]:
    if job.exec_seconds is None or baseline["std"] == 0:
        return None
    z_score = (job.exec_seconds - baseline["mean"]) / baseline["std"]
    if abs(z_score) > DEVIATION_SIGMA:
        return {
            "job_id": job.job_id,
            "device_id": job.device_id,
            "z_score": round(z_score, 4),
            "exec_seconds": job.exec_seconds,
            "baseline_mean": round(baseline["mean"], 4),
            "baseline_std": round(baseline["std"], 4),
        }
    return None


def main():
    provider = get_provider()
    print(f"[module42] Using provider: {provider.provider_name}", file=sys.stderr)

    try:
        jobs = provider.get_job_history(limit=100)
    except Exception as e:
        emit("TIMING_DATA_FETCH_FAILED", {"error": str(e)})
        sys.exit(0)

    state = load_state()
    seen_ids = set(state.get("seen_ids", []))
    baselines = state.get("baselines", {})

    # Filter to new jobs only
    new_jobs = [j for j in jobs if j.job_id not in seen_ids]
    if not new_jobs:
        emit("TIMING_CHECK_CLEAN", {"message": "No new jobs since last check"})
        save_state(state)
        return

    # Group by device for per-device baselines
    by_device: Dict[str, List[JobRecord]] = {}
    for job in jobs:  # Use full history for baseline, not just new
        by_device.setdefault(job.device_id, []).append(job)

    alerts = []
    for device_id, device_jobs in by_device.items():
        # Build exec time list (skip None)
        exec_times = [j.exec_seconds for j in device_jobs if j.exec_seconds is not None]
        baseline = compute_baseline(exec_times[-ROLLING_WINDOW_JOBS:])
        
        if baseline:
            baselines[device_id] = baseline
            # Check new jobs against this baseline
            for job in new_jobs:
                if job.device_id != device_id:
                    continue
                anomaly = check_timing(job, baseline)
                if anomaly:
                    alerts.append(anomaly)

    if alerts:
        emit("QUEUE_SIDE_CHANNEL_ACTIVE", {
            "severity": "WARN",
            "confidence": 0.65,
            "alerts": alerts,
            "threshold_sigma": DEVIATION_SIGMA,
        })
    else:
        emit("TIMING_BASELINE_NORMAL", {
            "devices_tracked": len(baselines),
            "new_jobs_checked": len(new_jobs),
        })

    # Update state
    for job in new_jobs:
        seen_ids.add(job.job_id)
    state["seen_ids"] = list(seen_ids)
    state["baselines"] = baselines
    save_state(state)


if __name__ == "__main__":
    main()
