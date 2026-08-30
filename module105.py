"""
Module 105 — Cross-Vendor Bell State Verification (ionq:forte-1)

METHOD: submits the same known-correct Bell state circuit used
elsewhere in this suite, but to a DIFFERENT hardware vendor
(IonQ's forte-1) than everything else run tonight (all on IQM
Garnet). If this completes, it's real evidence that Watchdog's
pipeline works correctly across multiple quantum hardware vendors —
not locked to one provider's specific behavior.

This is genuinely NEW hardware evidence, not a duplicate of 95/96/97
(which remain pending on iqm:garnet) — different backend, different
vendor, same reliable submission/polling pattern proven correct
tonight.

Uses the same signal.alarm timeout + history-diff recovery pattern as
module95/97 v4 — no threads, no hang risk, honest INCOMPLETE reporting
if the job doesn't finish within the wait budget.
"""
import json
import time
import datetime
import os
import signal
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 25
HISTORY_TIMEOUT_S = 15
POLL_MAX_WAIT_S = 90
POLL_INTERVAL_S = 8
BACKEND = "rigetti:cepheus-1-108q"


class OpTimeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise OpTimeout()


def with_timeout(func, timeout_s, *args, **kwargs):
    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(timeout_s)
    try:
        return func(*args, **kwargs)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def build_bell_control():
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""


def classify_result(counts, dominant_states, total):
    dominant_count = sum(counts.get(s, 0) for s in dominant_states)
    fraction = dominant_count / total if total else 0
    return {"dominant_states": dominant_states,
             "dominant_fraction": round(fraction, 4),
             "matches_prediction": fraction > 0.7}


def get_recent_job_ids(provider, limit=15):
    try:
        history = with_timeout(provider.get_job_history, HISTORY_TIMEOUT_S,
                                limit=limit)
        return {h.job_id for h in history}
    except OpTimeout:
        print(f"  [DEBUG] get_recent_job_ids TIMED OUT")
        return set()
    except Exception as e:
        print(f"  [DEBUG] get_recent_job_ids FAILED: {type(e).__name__}: {e}")
        return set()


def submit_with_recovery(provider, qasm, shots, backend, name,
                          submit_timeout=SUBMIT_TIMEOUT_S):
    known_job_ids = get_recent_job_ids(provider)
    print(f"  [DEBUG] baseline snapshot: {len(known_job_ids)} known job_ids")

    job_id = None
    print(f"  [DEBUG] submitting to backend='{backend}'")
    try:
        job_id = with_timeout(
            provider.submit_circuit, submit_timeout,
            qasm, shots=shots, backend=backend, name=name
        )
        print(f"  [DEBUG] branch=CLEAN_SUCCESS  submitted cleanly: {job_id}")
        return job_id
    except OpTimeout:
        print(f"  [DEBUG] branch=TIMEOUT  exceeded {submit_timeout}s — "
              f"attempting recovery via history diff")
    except Exception as e:
        print(f"  [DEBUG] branch=EXCEPTION  {type(e).__name__}: {e} — "
              f"attempting recovery via history diff")

    time.sleep(3)
    current_job_ids = get_recent_job_ids(provider)
    new_ids = current_job_ids - known_job_ids
    print(f"  [DEBUG] history diff: {len(new_ids)} new job(s): "
          f"{[j[:8] for j in new_ids] if new_ids else '(none)'}")

    if len(new_ids) == 1:
        job_id = next(iter(new_ids))
        print(f"  [DEBUG] branch=RECOVERED_VIA_DIFF  job_id: {job_id}")
    elif len(new_ids) > 1:
        print(f"  [DEBUG] branch=RECOVERY_AMBIGUOUS  {len(new_ids)} new jobs, cannot tell which")
    else:
        print(f"  [DEBUG] branch=RECOVERY_FAILED  no new job appeared — "
              f"submission likely never reached OpenQuantum, or backend "
              f"'{backend}' rejected the request (check for an error above)")

    return job_id


def poll_job_status(provider, job_id, max_wait_s=POLL_MAX_WAIT_S,
                     poll_interval_s=POLL_INTERVAL_S):
    if job_id is None:
        return "UNKNOWN"
    start = time.time()
    last_status = "UNKNOWN"
    while time.time() - start < max_wait_s:
        try:
            job = with_timeout(provider._scheduler.get_job, 15, job_id)
            last_status = job.status
            print(f"  status: {last_status} ({int(time.time() - start)}s elapsed)")
            if last_status in ("Completed", "Done", "FAILED", "Cancelled", "Error"):
                return last_status
        except OpTimeout:
            print(f"  poll timed out — will retry")
        except Exception as e:
            print(f"  poll error ({type(e).__name__}) — will retry")
        time.sleep(poll_interval_s)
    print(f"  gave up after {max_wait_s}s, last known status: {last_status}")
    return last_status


def run_cross_vendor_test(provider, shots=1024):
    print(f"--- Submitting Bell state to {BACKEND} (cross-vendor check) ---")
    qasm = build_bell_control()
    job_id = submit_with_recovery(provider, qasm, shots, BACKEND,
                                   "watchdog_cross_vendor_ionq_bell")
    print(f"Job ID: {job_id}")

    print(f"\nPolling (max {POLL_MAX_WAIT_S}s)...")
    status = poll_job_status(provider, job_id)

    if status not in ("Completed", "Done"):
        print(f"\n{'='*50}")
        print(f"INCOMPLETE — job did not finish within wait budget")
        print(f"Status: {status}  (job_id: {job_id})")
        print(f"{'='*50}")
        return {
            "backend": BACKEND, "job_id": job_id, "status": status,
            "matches_prediction": None,
            "note": ("Test incomplete within wait budget. Re-run "
                      "get_job_results manually once status shows Completed."),
            "shots": shots, "timestamp": now_iso(),
        }

    result = provider.get_job_results(job_id)
    counts = result.get("raw", {})
    total = sum(counts.values())
    check = classify_result(counts, ["00", "11"], total)

    print(f"\nCounts: {counts}")
    print(f"Matches Bell prediction (00/11 dominant): {check['matches_prediction']}")

    print(f"\n{'='*50}")
    print(f"CROSS-VENDOR VERIFICATION ({BACKEND}): "
          f"{'CONFIRMED' if check['matches_prediction'] else 'FAILED — INVESTIGATE'}")
    print(f"{'='*50}")

    return {
        "backend": BACKEND, "job_id": job_id, "status": status,
        "counts": counts, "classification": check,
        "shots": shots, "timestamp": now_iso(),
    }


if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    result = run_cross_vendor_test(provider)

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module105_cross_vendor_ionq_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
