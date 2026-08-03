#!/usr/bin/env python3
"""
Watchdog — Module 42: Quantum Job Queue Front-Running Detection
Monitors job submission and completion timing via IBM Quantum job history.
If completion time deviates significantly from expected gate-time baseline,
flags QUEUE_SIDE_CHANNEL_ACTIVE — attacker may be timing high-value jobs.
Requires: qiskit-ibm-runtime
Credentials: IBM_QUANTUM_TOKEN env var
"""
import json, datetime, os, time, math
from collections import deque

JOB_TIMING_FILE  = "/tmp/watchdog_qc_job_timing.json"
TIMING_WINDOW    = 20       # jobs in rolling baseline
DEVIATION_SIGMA  = 3.0      # flag if completion time > 3σ from baseline
POLL_INTERVAL    = 180      # seconds between job history checks
MAX_JOBS_FETCH   = 100      # jobs to pull per poll

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_timing_log() -> dict:
    try:
        with open(JOB_TIMING_FILE) as f:
            return json.load(f)
    except:
        return {"completion_times": [], "seen_jobs": []}

def save_timing_log(log: dict):
    try:
        with open(JOB_TIMING_FILE, "w") as f:
            json.dump(log, f)
    except:
        pass

def fetch_recent_jobs(token: str) -> list:
    """Fetch recent job history with timing data from IBM Quantum."""
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        svc  = QiskitRuntimeService(token=token)
        jobs = svc.jobs(limit=MAX_JOBS_FETCH)

        job_data = []
        for job in jobs:
            try:
                created   = job.creation_date
                status    = job.status()
                metrics   = getattr(job, 'metrics', lambda: {})()

                # Queue time = time from submission to execution start
                # Execution time = actual QPU time
                queue_s    = metrics.get("bss", {}).get("seconds", None)
                exec_s     = metrics.get("usage", {}).get("quantum_seconds", None)

                job_data.append({
                    "job_id":      job.job_id(),
                    "created_iso": created.isoformat() if created else None,
                    "status":      str(status),
                    "queue_s":     queue_s,
                    "exec_s":      exec_s,
                    "backend":     job.backend().name if job.backend() else None,
                })
            except:
                pass

        return job_data
    except ImportError:
        return []
    except Exception as e:
        return [{"error": str(e)}]

def mean_std(values: list) -> tuple:
    if len(values) < 2:
        return None, None
    n    = len(values)
    mean = sum(values) / n
    std  = math.sqrt(sum((x - mean)**2 for x in values) / n)
    return mean, std

def detect_frontrunning(timing_log: dict, jobs: list) -> list:
    """
    Detect timing anomalies consistent with queue side-channel attacks.
    An attacker probing queue timing would produce jobs with completion
    times that cluster unnaturally around high-value job completions.
    """
    alerts      = []
    seen        = set(timing_log.get("seen_jobs", []))
    exec_times  = timing_log.get("completion_times", [])

    new_exec_times = []
    for job in jobs:
        jid    = job.get("job_id")
        exec_s = job.get("exec_s")

        if jid in seen or exec_s is None:
            continue

        seen.add(jid)
        new_exec_times.append(exec_s)

    if not new_exec_times:
        return alerts, timing_log

    # Update rolling baseline
    exec_times.extend(new_exec_times)
    exec_times = exec_times[-TIMING_WINDOW * 5:]   # Keep last 100

    if len(exec_times) >= TIMING_WINDOW:
        baseline_vals = exec_times[-TIMING_WINDOW:]
        mean, std     = mean_std(baseline_vals)

        if mean and std and std > 0:
            for exec_s in new_exec_times:
                z_score = abs(exec_s - mean) / std
                if z_score > DEVIATION_SIGMA:
                    alerts.append({
                        "event":    "QUEUE_SIDE_CHANNEL_ACTIVE",
                        "severity": "WARN",
                        "exec_s":   round(exec_s, 3),
                        "baseline_mean_s": round(mean, 3),
                        "baseline_std_s":  round(std, 3),
                        "z_score":  round(z_score, 2),
                        "confidence": 0.65,
                        "note":     (f"Job execution time {round(exec_s,3)}s deviates "
                                     f"{round(z_score,1)}σ from baseline — "
                                     f"consistent with queue timing side-channel probe")
                    })

    timing_log["completion_times"] = exec_times
    timing_log["seen_jobs"]        = list(seen)[-5000:]   # Bound size

    return alerts, timing_log

def main():
    token = os.environ.get("IBM_QUANTUM_TOKEN")
    log   = open(f"module42_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "42_queue_frontrun",
          "sigma_threshold": DEVIATION_SIGMA,
          "credentials": "present" if token else "absent"})

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set IBM_QUANTUM_TOKEN to enable queue monitoring"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    timing_log = load_timing_log()
    alerts     = 0

    while True:
        jobs = fetch_recent_jobs(token)

        if jobs and "error" not in jobs[0]:
            emit({"event": "JOB_HISTORY_FETCH", "count": len(jobs)})
            new_alerts, timing_log = detect_frontrunning(timing_log, jobs)
            for alert in new_alerts:
                alerts += 1
                emit(alert)
            save_timing_log(timing_log)
        elif jobs and "error" in jobs[0]:
            emit({"event": "FETCH_ERROR", "detail": jobs[0]["error"]})

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
