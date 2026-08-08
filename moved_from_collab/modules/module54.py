#!/usr/bin/env python3
"""
Watchdog — Module 54: Session & Reservation Hijacking Detection (Refactored)
"""
import json, os, sys, statistics
from datetime import datetime, timezone, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from quantum_providers import get_provider, IBMQuantumProvider

QUEUE_TIME_TOLERANCE_S   = 30
UTILIZATION_FLOOR        = 0.40
SESSION_CHANGE_LIMIT     = 1
PENDING_JOBS_TOLERANCE   = 0
LOOKBACK_JOBS            = 100
STATE_PATH               = os.path.expanduser("~/watchdog_session_state.json")

def emit(event_type, details):
    print(json.dumps({
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **details
    }))

def load_state():
    if not os.path.exists(STATE_PATH):
        return {"sessions": {}, "seen_jobs": [], "queue_times": []}
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except:
        return {"sessions": {}, "seen_jobs": [], "queue_times": []}

def save_state(s):
    s["seen_jobs"] = s.get("seen_jobs", [])[-2000:]
    s["queue_times"] = s.get("queue_times", [])[-200:]
    with open(STATE_PATH, "w") as f:
        json.dump(s, f)

def parse_iso(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except:
        return None

def get_reservation_window():
    start = os.getenv("WD_RESERVATION_START")
    end   = os.getenv("WD_RESERVATION_END")
    return parse_iso(start) if start else None, parse_iso(end) if end else None

def in_window(ts, start, end):
    if start is None or end is None or ts is None:
        return False
    return start <= ts <= end

def fetch_jobs_and_sessions(service, backend_name=None):
    """Get recent jobs and backend status."""
    try:
        jobs = service.jobs(limit=LOOKBACK_JOBS)
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
                    "job_id": job.job_id(),
                    "session_id": session_id,
                    "created": created.isoformat() if created else None,
                    "created_dt": created,
                    "queue_s": queue_s,
                    "exec_s": exec_s,
                    "status": str(job.status()),
                    "backend": job.backend().name if job.backend() else None,
                })
            except:
                pass

        # Backend status
        backend_status = {}
        try:
            if backend_name:
                backend = service.backend(backend_name)
            else:
                backend = service.least_busy(operational=True, simulator=False)
            st = backend.status()
            backend_status = {
                "backend": backend.name,
                "pending_jobs": st.pending_jobs,
                "operational": st.operational,
            }
        except:
            pass

        return {"jobs": records, "backend_status": backend_status}
    except Exception as e:
        return {"error": str(e)}

def analyse_sessions(data, state, res_start, res_end):
    alerts = []
    jobs = data.get("jobs", [])
    status = data.get("backend_status", {})
    seen = set(state.get("seen_jobs", []))
    new_jobs = [j for j in jobs if j["job_id"] not in seen]
    for j in new_jobs:
        seen.add(j["job_id"])

    has_window = res_start is not None and res_end is not None
    now_dt = datetime.now(timezone.utc)
    currently_reserved = has_window and res_start <= now_dt <= res_end

    # 1. Queue time inside a reservation window
    if has_window:
        window_jobs = [j for j in jobs if in_window(j.get("created_dt"), res_start, res_end)]
        queued = [j for j in window_jobs if j.get("queue_s") is not None and j["queue_s"] > QUEUE_TIME_TOLERANCE_S]
        if queued:
            worst = max(queued, key=lambda j: j["queue_s"])
            alerts.append({
                "event": "RESERVATION_NOT_HONOURED",
                "severity": "CRITICAL",
                "jobs_queued_in_window": len(queued),
                "worst_queue_s": round(worst["queue_s"], 1),
                "tolerance_s": QUEUE_TIME_TOLERANCE_S,
                "window_start": res_start.isoformat(),
                "window_end": res_end.isoformat(),
                "confidence": 0.85,
                "note": "Jobs queued during an exclusive reservation window",
            })

        # 2. Utilization
        if window_jobs:
            window_s = (res_end - res_start).total_seconds()
            used_s = sum(j.get("exec_s") or 0 for j in window_jobs)
            if window_s > 0:
                util = used_s / window_s
                if util < UTILIZATION_FLOOR and now_dt > res_end:
                    alerts.append({
                        "event": "RESERVATION_UNDERUTILIZED",
                        "severity": "INFO",
                        "utilization": round(util, 3),
                        "floor": UTILIZATION_FLOOR,
                        "window_s": round(window_s, 1),
                        "used_s": round(used_s, 1),
                        "job_count": len(window_jobs),
                        "confidence": 0.60,
                        "note": "Paid reservation window largely unused by tenant",
                    })

    # 3. Pending jobs during exclusive window
    if currently_reserved and status:
        pending = status.get("pending_jobs", 0)
        if pending > PENDING_JOBS_TOLERANCE:
            alerts.append({
                "event": "EXCLUSIVE_WINDOW_CONTENDED",
                "severity": "CRITICAL",
                "backend": status.get("backend"),
                "pending_jobs": pending,
                "tolerance": PENDING_JOBS_TOLERANCE,
                "confidence": 0.80,
                "note": "Backend has pending jobs during exclusive reservation",
            })

    # 4. Session ID stability
    sessions = state.get("sessions", {})
    session_counts = defaultdict(int)
    for j in new_jobs:
        sid = j.get("session_id")
        if sid:
            session_counts[sid] += 1
            sessions[sid] = sessions.get(sid, 0) + 1

    if len(session_counts) > SESSION_CHANGE_LIMIT + 1:
        alerts.append({
            "event": "SESSION_FRAGMENTATION",
            "severity": "INFO",
            "distinct_sessions": len(session_counts),
            "sessions": dict(list(session_counts.items())[:5]),
            "confidence": 0.60,
            "note": "Jobs spread across multiple session IDs in one poll window",
        })

    # 5. Jobs with no session during reservation
    if currently_reserved:
        sessionless = [j for j in new_jobs if not j.get("session_id")]
        if sessionless:
            alerts.append({
                "event": "JOBS_OUTSIDE_SESSION",
                "severity": "INFO",
                "count": len(sessionless),
                "confidence": 0.55,
                "note": "Jobs executed with no session ID during a reservation window",
            })

    # 6. Queue time baseline drift
    qts = [j["queue_s"] for j in new_jobs if j.get("queue_s") is not None]
    history = state.get("queue_times", [])
    if qts and len(history) >= 20:
        baseline = statistics.median(history)
        current  = statistics.median(qts)
        if baseline > 0 and current > baseline * 5:
            alerts.append({
                "event": "QUEUE_TIME_ANOMALY",
                "severity": "INFO",
                "current_median_s": round(current, 1),
                "baseline_median_s": round(baseline, 1),
                "ratio": round(current / baseline, 2),
                "confidence": 0.60,
                "note": "Queue times far above baseline – possible priority demotion",
            })
    history.extend(qts)

    state["seen_jobs"] = list(seen)
    state["sessions"] = sessions
    state["queue_times"] = history

    return alerts, state, len(new_jobs)

def main():
    provider = get_provider()
    if not isinstance(provider, IBMQuantumProvider):
        emit("PROVIDER_NOT_SUPPORTED", {"provider": provider.provider_name,
                                        "note": "Module54 requires IBM Quantum"})
        return

    # Access the internal service (since we need the raw service for jobs)
    service = provider._service

    res_start, res_end = get_reservation_window()
    emit("RUN_START", {
        "module": "54_session_hijacking",
        "queue_tolerance_s": QUEUE_TIME_TOLERANCE_S,
        "utilization_floor": UTILIZATION_FLOOR,
        "reservation_window": {
            "start": res_start.isoformat() if res_start else None,
            "end": res_end.isoformat() if res_end else None,
        },
        "provider": provider.provider_name,
    })

    if res_start is None:
        emit("NO_RESERVATION_DECLARED", {
            "note": "Set WD_RESERVATION_START and WD_RESERVATION_END for strict checks",
        })

    state = load_state()
    backend_name = os.getenv("IBM_QUANTUM_BACKEND")
    data = fetch_jobs_and_sessions(service, backend_name)

    if "error" in data:
        emit("FETCH_ERROR", {"detail": data["error"]})
    else:
        alerts, state, new_count = analyse_sessions(data, state, res_start, res_end)
        emit("SESSION_POLL", {
            "new_jobs": new_count,
            "backend_status": data.get("backend_status", {}),
        })
        for a in alerts:
            emit(a["event"], a)
        save_state(state)

    alert_count = sum(1 for a in alerts if a.get("severity") in ("CRITICAL","WARN"))
    emit("RUN_END", {"alerts": alert_count})

if __name__ == "__main__":
    main()
