#!/usr/bin/env python3
"""
Watchdog — Module 45: Quantum Cloud Credential Drain Detection
Monitors QaaS job history for burst activity consistent with stolen API keys.
Flags if excessive shots, circuits, or spend detected in a short window.

Note on auto-rotation: IBM Quantum does not expose a programmatic key
rotation endpoint. Flagging here triggers manual action or incident response.
If using IBM Quantum Platform, key rotation is manual via the web console.
Requires: qiskit-ibm-runtime
Credentials: IBM_QUANTUM_TOKEN env var

Quantum physics/cost model integration: reports the estimated dollar cost
of a detected shot-burst using M_qubit_hour_economics, so the alert carries
a concrete financial number, not just a raw shot/job count.
"""
import json, datetime, os, time, sys
from collections import deque

sys.path.append("/data/data/com.termux/files/home/Watchdog/quantum_models")
try:
    from M_qubit_hour_economics import cost_per_shot
except ImportError:
    cost_per_shot = 0.001  # fallback: $0.001/shot if model unavailable

DRAIN_WINDOW_S      = 3600     # 1 hour rolling window
MAX_SHOTS_PER_HOUR  = 100_000  # flag if total shots exceed this
MAX_JOBS_PER_HOUR   = 200      # flag if total jobs exceed this
MAX_CIRCUITS_PER_JOB = 50      # flag if single job has this many circuits
POLL_INTERVAL       = 300      # seconds between checks
JOB_LOG_FILE        = "/tmp/watchdog_qc_job_log.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_job_log() -> dict:
    try:
        with open(JOB_LOG_FILE) as f:
            return json.load(f)
    except Exception:
        return {"jobs": []}

def save_job_log(log: dict):
    now_ts = time.time()
    # Prune jobs older than drain window
    log["jobs"] = [j for j in log["jobs"] if now_ts - j.get("ts", 0) < DRAIN_WINDOW_S * 2]
    try:
        with open(JOB_LOG_FILE, "w") as f:
            json.dump(log, f)
    except Exception:
        pass

def fetch_job_history(token: str) -> list:
    """Fetch recent job history from IBM Quantum Runtime."""
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        svc  = QiskitRuntimeService(token=token)
        jobs = svc.jobs(limit=200)

        job_records = []
        for job in jobs:
            try:
                inputs = job.inputs or {}
                shots  = inputs.get("shots", 0) if isinstance(inputs, dict) else 0
                # Count circuits from run_input
                run_input = inputs.get("run_input", []) if isinstance(inputs, dict) else []
                n_circuits = len(run_input) if isinstance(run_input, list) else 1

                job_records.append({
                    "job_id":     job.job_id(),
                    "shots":      shots,
                    "n_circuits": n_circuits,
                    "created":    job.creation_date.isoformat() if job.creation_date else None,
                    "status":     str(job.status()),
                    "ts":         job.creation_date.timestamp() if job.creation_date else time.time(),
                })
            except Exception:
                pass

        return job_records
    except ImportError:
        return []
    except Exception as e:
        return [{"error": str(e)}]

def detect_credential_drain(job_log: dict, new_jobs: list) -> list:
    """Detect burst activity consistent with credential theft and drain."""
    alerts    = []
    now_ts    = time.time()
    seen_ids  = {j["job_id"] for j in job_log["jobs"] if "job_id" in j}
    window_ts = now_ts - DRAIN_WINDOW_S

    # Add new jobs not yet logged
    for job in new_jobs:
        if "error" in job:
            continue
        jid = job.get("job_id")
        if jid and jid not in seen_ids:
            job_log["jobs"].append(job)

    # Analyse jobs within window
    window_jobs = [j for j in job_log["jobs"] if j.get("ts", 0) >= window_ts]
    total_shots    = sum(j.get("shots", 0) for j in window_jobs)
    total_jobs     = len(window_jobs)

    if total_shots > MAX_SHOTS_PER_HOUR:
        alerts.append({
            "event":    "CREDENTIAL_DRAIN_SHOTS",
            "severity": "CRITICAL",
            "total_shots_in_window": total_shots,
            "threshold": MAX_SHOTS_PER_HOUR,
            "window_s": DRAIN_WINDOW_S,
            "estimated_cost_usd": round(total_shots * cost_per_shot, 2),
            "confidence": 0.85,
            "note":     ("Excessive shots in 1-hour window — consistent with "
                         "stolen API key running maximum workloads"),
            "action":   "Rotate IBM_QUANTUM_TOKEN immediately via quantum.cloud.ibm.com"
        })

    if total_jobs > MAX_JOBS_PER_HOUR:
        alerts.append({
            "event":    "CREDENTIAL_DRAIN_JOBS",
            "severity": "CRITICAL",
            "total_jobs_in_window": total_jobs,
            "threshold": MAX_JOBS_PER_HOUR,
            "window_s": DRAIN_WINDOW_S,
            "estimated_cost_usd": round(total_shots * cost_per_shot, 2),
            "confidence": 0.80,
            "note":     "Abnormal job count — possible credential drain",
            "action":   "Rotate IBM_QUANTUM_TOKEN immediately"
        })

    # Flag individual jobs with massive circuit counts
    for job in window_jobs:
        if job.get("n_circuits", 0) > MAX_CIRCUITS_PER_JOB:
            alerts.append({
                "event":     "LARGE_CIRCUIT_BURST",
                "severity":  "WARN",
                "job_id":    job.get("job_id"),
                "n_circuits": job.get("n_circuits"),
                "threshold": MAX_CIRCUITS_PER_JOB,
                "estimated_cost_usd": round(job.get("shots", 0) * cost_per_shot, 2),
                "confidence": 0.70,
                "note":      "Single job with unusually large circuit count"
            })

    return alerts, job_log

def main():
    token = os.environ.get("IBM_QUANTUM_TOKEN")
    log   = open(f"module45_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "45_credential_drain",
          "thresholds": {
              "max_shots_per_hour":    MAX_SHOTS_PER_HOUR,
              "max_jobs_per_hour":     MAX_JOBS_PER_HOUR,
              "max_circuits_per_job":  MAX_CIRCUITS_PER_JOB,
          },
          "cost_per_shot_usd": cost_per_shot,
          "credentials": "present" if token else "absent"})

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set IBM_QUANTUM_TOKEN to enable credential drain monitoring"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    job_log = load_job_log()
    alerts  = 0

    while True:
        new_jobs = fetch_job_history(token)
        if new_jobs and "error" not in new_jobs[0]:
            emit({"event": "JOB_HISTORY_FETCH", "count": len(new_jobs)})
            new_alerts, job_log = detect_credential_drain(job_log, new_jobs)
            for alert in new_alerts:
                alerts += 1
                emit(alert)
            save_job_log(job_log)
        elif new_jobs and "error" in new_jobs[0]:
            emit({"event": "FETCH_ERROR", "detail": new_jobs[0].get("error")})

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
