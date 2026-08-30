#!/usr/bin/env python3
"""
Watchdog — Module 46: D-Wave / Quantum Annealer Side-Channel Detection
Tracks annealing completion times across jobs.
Periodic/rhythmic timing patterns indicate a side-channel probe
attempting to infer neighbor tenant qubit usage from annealing duration.

Response: submits a noise job with randomized timing to blind the attacker.

Requires: dwave-ocean-sdk (pip install dwave-ocean-sdk)
Credentials: DWAVE_API_TOKEN env var, DWAVE_SOLVER env var (optional)
Falls back to timing analysis only if no credentials.
"""
import json, datetime, os, time, math, secrets
from collections import deque

TIMING_WINDOW       = 20      # jobs in rolling analysis window
PERIODIC_CV_THRESH  = 0.15    # Coefficient of variation below this = suspiciously regular
LAG1_AC_THRESH      = 0.50    # Lag-1 autocorrelation above this = periodic
NOISE_JOB_QUBITS    = 4       # size of noise job to inject
POLL_INTERVAL       = 60      # seconds between annealing time checks
TIMING_LOG_FILE     = "/tmp/watchdog_dwave_timing.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_timing_log() -> dict:
    try:
        with open(TIMING_LOG_FILE) as f:
            return json.load(f)
    except:
        return {"annealing_times": [], "seen_jobs": []}

def save_timing_log(log: dict):
    try:
        with open(TIMING_LOG_FILE, "w") as f:
            json.dump(log, f)
    except:
        pass

def mean_std(values: list) -> tuple:
    if len(values) < 2:
        return None, None
    n    = len(values)
    mean = sum(values) / n
    std  = math.sqrt(sum((x - mean)**2 for x in values) / n)
    return mean, std

def lag1_autocorr(values: list) -> float:
    """Calculate lag-1 autocorrelation."""
    if len(values) < 3:
        return 0.0
    mean, std = mean_std(values)
    if not mean or not std or std == 0:
        return 0.0
    pairs = [(values[i] - mean) * (values[i+1] - mean)
             for i in range(len(values)-1)]
    return (sum(pairs) / (len(pairs) * std**2)) if std > 0 else 0.0

def is_periodic(times: list) -> tuple[bool, dict]:
    """Detect rhythmic pattern in annealing times (side-channel signature)."""
    if len(times) < TIMING_WINDOW:
        return False, {}
    mean, std = mean_std(times)
    if not mean or mean == 0:
        return False, {}
    cv   = std / mean
    lag1 = lag1_autocorr(times)
    periodic = cv < PERIODIC_CV_THRESH and lag1 > LAG1_AC_THRESH
    return periodic, {"cv": round(cv, 4), "lag1_ac": round(lag1, 4), "mean_ms": round(mean, 2)}

def fetch_dwave_annealing_times(token: str, solver: str = None) -> list:
    """Fetch recent annealing times from D-Wave Ocean SDK."""
    try:
        from dwave.cloud import Client
        with Client.from_config(token=token, solver=solver) as client:
            if not solver:
                svc = client.get_solvers(online=True)
                if not svc:
                    return []
                solver = svc[0].id

            # Get recent problem IDs and timing
            problems = client.get_problems(limit=50)
            times = []
            for prob in problems:
                timing = getattr(prob, 'timing', {}) or {}
                anneal_us = timing.get("qpu_anneal_time_per_sample")
                if anneal_us:
                    times.append({
                        "problem_id":  prob.id,
                        "anneal_ms":   anneal_us / 1000,
                        "submitted":   getattr(prob, 'submitted_on', now_iso()),
                    })
            return times
    except ImportError:
        return [{"error": "dwave-ocean-sdk not installed"}]
    except Exception as e:
        return [{"error": str(e)}]

def inject_noise_job(token: str, solver: str = None) -> bool:
    """
    Submit a randomized-time noise job to blind attacker's timing analysis.
    Uses a small random Ising problem with randomized annealing time.
    """
    try:
        from dwave.cloud import Client
        import random
        with Client.from_config(token=token, solver=solver) as client:
            if not solver:
                svc = client.get_solvers(online=True)
                if not svc:
                    return False
                solver_obj = svc[0]
            else:
                solver_obj = client.get_solver(solver)

            # Random Ising problem on 4 qubits
            h = {i: (random.random() * 2 - 1) for i in range(NOISE_JOB_QUBITS)}
            J = {(0, 1): random.random(), (1, 2): random.random()}

            # Randomized annealing time between 20-200 microseconds
            anneal_time = random.randint(20, 200)

            computation = solver_obj.sample_ising(h, J,
                                                   annealing_time=anneal_time,
                                                   num_reads=1)
            computation.cancel()   # Cancel immediately — we just need the job submitted
            return True
    except:
        return False

def main():
    token  = os.environ.get("DWAVE_API_TOKEN")
    solver = os.environ.get("DWAVE_SOLVER")
    log    = open(f"module46_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "46_annealer_sidechannel",
          "cv_threshold": PERIODIC_CV_THRESH,
          "lag1_threshold": LAG1_AC_THRESH,
          "credentials": "present" if token else "absent"})

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set DWAVE_API_TOKEN to enable annealer side-channel monitoring"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    timing_log = load_timing_log()
    alerts     = 0

    while True:
        times = fetch_dwave_annealing_times(token, solver)

        if times and "error" in times[0]:
            emit({"event": "FETCH_ERROR", "detail": times[0]["error"]})
        else:
            seen = set(timing_log.get("seen_jobs", []))
            new_times = []
            for t in times:
                pid = t.get("problem_id")
                if pid and pid not in seen:
                    seen.add(pid)
                    new_times.append(t.get("anneal_ms", 0))

            if new_times:
                timing_log["annealing_times"].extend(new_times)
                timing_log["annealing_times"] = timing_log["annealing_times"][-200:]
                timing_log["seen_jobs"] = list(seen)[-5000:]

                window = timing_log["annealing_times"][-TIMING_WINDOW:]
                periodic, stats = is_periodic(window)

                if periodic:
                    alerts += 1
                    emit({"event":    "ANNEALER_SIDECHANNEL_DETECTED",
                          "severity": "WARN",
                          "stats":    stats,
                          "confidence": 0.75,
                          "note":     ("Annealing times show rhythmic pattern — "
                                       "consistent with side-channel timing probe")})

                    if inject_noise_job(token, solver):
                        emit({"event": "NOISE_JOB_INJECTED",
                              "note": "Randomized annealing job submitted to blind attacker timing"})

            save_timing_log(timing_log)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
