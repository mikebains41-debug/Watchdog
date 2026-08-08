#!/usr/bin/env python3
"""
Watchdog — Module 45: Credential Drain Detection
Refactored to use quantum_providers abstraction layer.
"""
import json, os, sys
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quantum_providers import get_provider, JobRecord

# Physics layer integration — cost per usable qubit-hour
try:
    from quantum_models.physics_bridge import cost_per_shot
except Exception:
    def cost_per_shot(shots: int, _qubits: int = 1) -> float:
        return shots * 0.001

MAX_SHOTS_PER_HOUR = 100_000
MAX_JOBS_PER_HOUR = 200
MAX_CIRCUITS_PER_JOB = 50
ROLLING_WINDOW_S = 3600
STATE_PATH = os.path.expanduser("~/watchdog_qc_drain_state.json")


def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_PATH):
        return {"seen_jobs": {}, "last_alert": {}}
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"seen_jobs": {}, "last_alert": {}}


def save_state(state: Dict[str, Any]) -> None:
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, default=str)


def emit(event_type: str, details: Dict[str, Any]) -> None:
    print(json.dumps({
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **details
    }))


def analyze_jobs(jobs: List[JobRecord], state: Dict[str, Any]) -> None:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=ROLLING_WINDOW_S)

    recent = []
    for job in jobs:
        created = job.created_at
        if created is None:
            continue
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if created >= cutoff:
            recent.append(job)

    total_shots = sum(j.shots for j in recent)
    total_jobs = len(recent)
    max_circuits = max((j.circuit_count for j in recent), default=0)
    estimated_cost = cost_per_shot(total_shots)

    if total_shots > MAX_SHOTS_PER_HOUR:
        emit("CREDENTIAL_DRAIN_SHOTS", {
            "severity": "CRITICAL",
            "confidence": 0.85,
            "shots_in_window": total_shots,
            "threshold": MAX_SHOTS_PER_HOUR,
            "estimated_cost_usd": round(estimated_cost, 4),
            "window_s": ROLLING_WINDOW_S,
            "remediation": "Rotate API key via provider web console immediately",
        })

    if total_jobs > MAX_JOBS_PER_HOUR:
        emit("CREDENTIAL_DRAIN_JOBS", {
            "severity": "CRITICAL",
            "confidence": 0.80,
            "jobs_in_window": total_jobs,
            "threshold": MAX_JOBS_PER_HOUR,
            "window_s": ROLLING_WINDOW_S,
            "remediation": "Rotate API key via provider web console immediately",
        })

    if max_circuits > MAX_CIRCUITS_PER_JOB:
        emit("LARGE_CIRCUIT_BURST", {
            "severity": "WARN",
            "max_circuits_in_single_job": max_circuits,
            "threshold": MAX_CIRCUITS_PER_JOB,
        })

    if total_shots <= MAX_SHOTS_PER_HOUR and total_jobs <= MAX_JOBS_PER_HOUR:
        emit("CREDENTIAL_USAGE_NORMAL", {
            "shots_in_window": total_shots,
            "jobs_in_window": total_jobs,
            "estimated_cost_usd": round(estimated_cost, 4),
        })


def main():
    provider = get_provider()
    print(f"[module45] Using provider: {provider.provider_name}", file=sys.stderr)

    try:
        jobs = provider.get_job_history(limit=200)
    except Exception as e:
        emit("JOB_HISTORY_FETCH_FAILED", {"error": str(e)})
        sys.exit(0)

    state = load_state()
    analyze_jobs(jobs, state)

    for job in jobs:
        state["seen_jobs"][job.job_id] = datetime.now(timezone.utc).isoformat()
    save_state(state)


if __name__ == "__main__":
    main()
