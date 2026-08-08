#!/usr/bin/env python3
"""
Watchdog — Module 54: Session & Reservation Hijacking Detection

Attack vector: QaaS providers sell dedicated instances and reserved time
windows. During a reservation the tenant is supposed to have exclusive
access to a QPU. Nothing on the tenant side verifies that:

  - The reserved window is actually being honoured
  - Their own jobs are the ones executing in that window
  - Another tenant's jobs are not being scheduled into the paid slot
  - A Session that should hold the QPU has not been silently closed
    and the tenant's jobs demoted back to the shared fair-share queue

Symptoms of a hijacked or unhonoured reservation are measurable:
  - Queue time inside a reservation window should be near zero.
    Non-zero queue time during a paid exclusive window means someone
    else is in the slot.
  - Job count executed during the window is far below what the window
    duration and average job runtime should allow.
  - A Session ID changes mid-window, or jobs fall back to a different
    execution mode than the one requested.
  - The backend's pending_jobs count is non-zero during what should be
    an exclusive reservation.

Requires: qiskit-ibm-runtime
Credentials: IBM_QUANTUM_TOKEN env var
Optional: WD_RESERVATION_START / WD_RESERVATION_END (ISO 8601) to declare
          a known reservation window for stricter checking.
"""
import json, datetime, os, time, statistics
from collections import deque, defaultdict

QUEUE_TIME_TOLERANCE_S   = 30      # queue time above this inside a reservation = flag
UTILIZATION_FLOOR        = 0.40    # <40% of the window used = flag
SESSION_CHANGE_LIMIT     = 1       # session ID changes mid-window before flagging
PENDING_JOBS_TOLERANCE   = 0       # pending jobs during exclusive window
POLL_INTERVAL            = 300     # seconds between checks
LOOKBACK_JOBS            = 100     # jobs to pull per poll
STATE_FILE               = "/tmp/watchdog_session_state.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"sessions": {}, "seen_jobs": [], "queue_times": []}

def save_state(s: dict):
    try:
        s["seen_jobs"]   = s.get("seen_jobs", [])[-2000:]
        s["queue_times"] = s.get("queue_times", [])[-200:]
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def parse_iso(value: str):
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except:
        return None

def get_reservation_window() -> tuple:
    """Read a declared reservation window from env, if set."""
    start = os.environ.get("WD_RESERVATION_START")
    end   = os.environ.get("WD_RESERVATION_END")
    return parse_iso(start) if start else None, parse_iso(end) if end else None

def in_window(ts, start, end) -> bool:
    if start is None or end is None or ts is None:
        return False
    return start <= ts <= end

def fetch_jobs_and_sessions(token: str) -> dict:
    """
    Pull recent jobs with their session IDs, queue times, execution times,
    and execution mode. Also pull current backend queue depth.
    """
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        svc = QiskitRuntimeService(token=token)

        jobs = svc.jobs(limit=LOOKBACK_JOBS)
        records = []

        for job in jobs:
            try:
                metrics = {}
                try:
                    metrics = job.metrics() or {}
                except:
                    pass

                created = job.creation_date
                queue_s = None
                exec_s  = None
                try:
                    queue_s = metrics.get("usage", {}).get("seconds")
                    ts = metrics.get("timestamps", {}) or {}
                    created_at = parse_iso(ts.get("created", "")) if ts.get("created") else None
                    running_at = parse_iso(ts.get("running", "")) if ts.get("running") else None
                    if created_at and running_at:
                        queue_s = (running_at - created_at).total_seconds()
                    exec_s = metrics.get("usage", {}).get("quantum_seconds")
                except:
                    pass

                session_id = None
                for attr in ("session_id", "_session_id"):
                    if hasattr(job, attr):
                        session_id = getattr(job, attr)
                        break

                records.append({
                    "job_id":     job.job_id(),
                    "session_id": session_id,
                    "created":    created.isoformat() if created else None,
                    "created_dt": created,
                    "queue_s":    queue_s,
                    "exec_s":     exec_s,
                    "status":     str(job.status()),
                    "backend":    job.backend().name if job.backend() else None,
                })
            except:
                pass

        # Current backend queue depth
        backend_status = {}
        try:
            backend_name = os.environ.get("IBM_QUANTUM_BACKEND")
            backend = (svc.backend(backend_name) if backend_name
                       else svc.least_busy(operational=True, simulator=False,
                                            min_num_qubits=5))
            st = backend.status()
            backend_status = {
                "backend":      backend.name,
                "pending_jobs": st.pending_jobs,
                "operational":  st.operational,
            }
        except:
            pass

        return {"jobs": records, "backend_status": backend_status}

    except ImportError:
        return {"error": "qiskit_ibm_runtime not installed"}
    except Exception as e:
        return {"error": str(e)}

def analyse_sessions(data: dict, state: dict,
                      res_start, res_end) -> tuple:
    """Detect reservation and session anomalies."""
    alerts = []
    jobs   = data.get("jobs", [])
    status = data.get("backend_status", {})
    seen   = set(state.get("seen_jobs", []))

    new_jobs = [j for j in jobs if j["job_id"] not in seen]
    for j in new_jobs:
        seen.add(j["job_id"])

    has_window = res_start is not None and res_end is not None
    now_dt     = datetime.datetime.now(datetime.timezone.utc)
    currently_reserved = has_window and res_start <= now_dt <= res_end

    # ── 1. Queue time inside a declared reservation window ──
    if has_window:
        window_jobs = [j for j in jobs
                       if in_window(j.get("created_dt"), res_start, res_end)]
        queued = [j for j in window_jobs
                  if j.get("queue_s") is not None
                  and j["queue_s"] > QUEUE_TIME_TOLERANCE_S]

        if queued:
            worst = max(queued, key=lambda j: j["queue_s"])
            alerts.append({
                "event":    "RESERVATION_NOT_HONOURED",
                "severity": "CRITICAL",
                "jobs_queued_in_window": len(queued),
                "worst_queue_s":  round(worst["queue_s"], 1),
                "tolerance_s":    QUEUE_TIME_TOLERANCE_S,
                "window_start":   res_start.isoformat(),
                "window_end":     res_end.isoformat(),
                "confidence": 0.85,
                "note": ("Jobs queued during a paid exclusive reservation. "
                         "Non-zero queue time inside a reservation means the "
                         "slot is being shared or the reservation is not active"),
            })

        # ── 2. Window utilization ──
        if window_jobs:
            window_s = (res_end - res_start).total_seconds()
            used_s   = sum(j.get("exec_s") or 0 for j in window_jobs)
            if window_s > 0:
                util = used_s / window_s
                if util < UTILIZATION_FLOOR and now_dt > res_end:
                    alerts.append({
                        "event":    "RESERVATION_UNDERUTILIZED",
                        "severity": "WARN",
                        "utilization": round(util, 3),
                        "floor":       UTILIZATION_FLOOR,
                        "window_s":    round(window_s, 1),
                        "used_s":      round(used_s, 1),
                        "job_count":   len(window_jobs),
                        "confidence": 0.60,
                        "note": ("Paid reservation window largely unused by the "
                                 "tenant's own jobs — verify the slot was not "
                                 "consumed by another tenant"),
                    })

    # ── 3. Pending jobs during an exclusive window ──
    if currently_reserved and status:
        pending = status.get("pending_jobs", 0)
        if pending > PENDING_JOBS_TOLERANCE:
            alerts.append({
                "event":    "EXCLUSIVE_WINDOW_CONTENDED",
                "severity": "CRITICAL",
                "backend":  status.get("backend"),
                "pending_jobs": pending,
                "tolerance":    PENDING_JOBS_TOLERANCE,
                "confidence": 0.80,
                "note": ("Backend reports pending jobs during what should be an "
                         "exclusive reservation. Another tenant is in the slot"),
            })

    # ── 4. Session ID stability ──
    sessions = state.get("sessions", {})
    session_counts = defaultdict(int)
    for j in new_jobs:
        sid = j.get("session_id")
        if sid:
            session_counts[sid] += 1
            sessions[sid] = sessions.get(sid, 0) + 1

    # More than one active session ID appearing in a short poll window,
    # when the tenant should be inside a single Session, means the session
    # was closed and jobs fell back to the shared queue.
    if len(session_counts) > SESSION_CHANGE_LIMIT + 1:
        alerts.append({
            "event":    "SESSION_FRAGMENTATION",
            "severity": "WARN",
            "distinct_sessions": len(session_counts),
            "sessions": dict(list(session_counts.items())[:5]),
            "confidence": 0.60,
            "note": ("Jobs spread across multiple session IDs in one poll "
                     "window. A Session that should hold the QPU may have been "
                     "closed, demoting jobs to the shared fair-share queue"),
        })

    # ── 5. Jobs with no session at all during a reservation ──
    if currently_reserved:
        sessionless = [j for j in new_jobs if not j.get("session_id")]
        if sessionless:
            alerts.append({
                "event":    "JOBS_OUTSIDE_SESSION",
                "severity": "WARN",
                "count":    len(sessionless),
                "confidence": 0.55,
                "note": ("Jobs executed with no session ID during a reservation "
                         "window — they are not protected by the reservation"),
            })

    # ── 6. Queue time baseline drift (works without a declared window) ──
    qts = [j["queue_s"] for j in new_jobs
           if j.get("queue_s") is not None]
    history = state.get("queue_times", [])
    if qts and len(history) >= 20:
        baseline = statistics.median(history)
        current  = statistics.median(qts)
        if baseline > 0 and current > baseline * 5:
            alerts.append({
                "event":    "QUEUE_TIME_ANOMALY",
                "severity": "WARN",
                "current_median_s":  round(current, 1),
                "baseline_median_s": round(baseline, 1),
                "ratio":             round(current / baseline, 2),
                "confidence": 0.60,
                "note": ("Queue times far above this account's own baseline — "
                         "possible priority demotion or slot contention"),
            })
    history.extend(qts)

    state["seen_jobs"]   = list(seen)
    state["sessions"]    = sessions
    state["queue_times"] = history

    return alerts, state, len(new_jobs)

def main():
    token = os.environ.get("IBM_QUANTUM_TOKEN")
    log   = open(f"module54_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    res_start, res_end = get_reservation_window()

    emit({"event": "RUN_START", "module": "54_session_hijacking",
          "queue_tolerance_s":  QUEUE_TIME_TOLERANCE_S,
          "utilization_floor":  UTILIZATION_FLOOR,
          "reservation_window": {
              "start": res_start.isoformat() if res_start else None,
              "end":   res_end.isoformat()   if res_end   else None,
          },
          "credentials": "present" if token else "absent"})

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set IBM_QUANTUM_TOKEN to enable session monitoring"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    if res_start is None:
        emit({"event": "NO_RESERVATION_DECLARED",
              "note": ("Set WD_RESERVATION_START and WD_RESERVATION_END (ISO 8601) "
                       "to enable strict reservation checking. Running in "
                       "baseline-drift mode only.")})

    state  = load_state()
    alerts = 0

    while True:
        data = fetch_jobs_and_sessions(token)

        if "error" in data:
            emit({"event": "FETCH_ERROR", "detail": data["error"]})
        else:
            new_alerts, state, new_count = analyse_sessions(
                data, state, res_start, res_end)

            emit({"event": "SESSION_POLL",
                  "new_jobs":       new_count,
                  "backend_status": data.get("backend_status", {})})

            for a in new_alerts:
                alerts += 1
                emit(a)

            save_state(state)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
