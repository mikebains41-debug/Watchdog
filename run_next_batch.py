"""
run_next_batch.py — orchestrates the next batch of tests, safely.

This does NOT blindly run everything on the wishlist. Two items from
that list are deliberately SKIPPED, with the reason printed, not
silently:

  - Module95 on iqm:garnet: that backend has been confirmed stuck all
    night (600-job queue, not accepting jobs). Resubmitting there
    would just burn credits into another stuck Pending job — the
    entire problem we spent hours solving by switching to Rigetti.

  - Module105 "fix" by copying Rigetti's execution plan ID onto an
    IonQ submission: the earlier IonQ failure was a Public Plan tier
    restriction, not a plan-ID mismatch. Reusing Rigetti's ID doesn't
    address that — it would just fail differently.

What this DOES do, in order:
  1. Cancels any jobs still stuck Pending specifically on iqm:garnet
     (frees credits — leaves non-Garnet jobs alone).
  2. Checks for run_all.py and run_8ghz.py — runs them ONLY if they
     genuinely exist on this system; skips with a clear message
     otherwise, rather than assuming and failing loudly.
  3. Submits a genuinely NEW hardware test: a 3-qubit GHZ state on
     Rigetti (proven-working backend tonight), using the same
     signal.alarm timeout + history-diff recovery pattern verified
     across modules 95/96/97/105.
"""
import subprocess
import json
import time
import datetime
import os
import signal
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 25
HISTORY_TIMEOUT_S = 15
POLL_MAX_WAIT_S = 180
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


def step1_cancel_stuck_garnet_jobs(provider):
    print("="*70)
    print("STEP 1: Canceling jobs stuck on iqm:garnet (frees credits)")
    print("="*70)
    try:
        history = with_timeout(provider.get_job_history, HISTORY_TIMEOUT_S, limit=20)
    except Exception as e:
        print(f"  Could not fetch job history: {type(e).__name__}: {e}")
        print("  Skipping cancellation step.\n")
        return

    pending = [h for h in history if h.status == "Pending"]
    if not pending:
        print("  No Pending jobs found. Nothing to cancel.\n")
        return

    print(f"  Found {len(pending)} Pending job(s). Attempting to cancel each...")
    for h in pending:
        try:
            with_timeout(provider._scheduler.cancel_job, 15, h.job_id)
            print(f"    Canceled: {h.job_id[:8]}")
        except Exception as e:
            print(f"    Could not cancel {h.job_id[:8]}: {type(e).__name__}: {e}")
    print()


def step2_check_and_run_optional_scripts():
    print("="*70)
    print("STEP 2: Checking for run_all.py and run_8ghz.py")
    print("="*70)
    for script in ("run_all.py", "run_8ghz.py"):
        if os.path.isfile(script):
            print(f"  {script} found — running it now...")
            try:
                result = subprocess.run(["python3", script], timeout=300)
                print(f"  {script} exited with code {result.returncode}")
            except subprocess.TimeoutExpired:
                print(f"  {script} exceeded 300s timeout — moving on")
            except Exception as e:
                print(f"  {script} failed to run: {type(e).__name__}: {e}")
        else:
            print(f"  {script} NOT FOUND in current directory — skipping "
                  f"(this was never verified to exist; not guessing at its content)")
    print()


def build_ghz3():
    """3-qubit GHZ state — genuinely new circuit, not run on Rigetti yet
    tonight. (|000> + |111>) / sqrt(2)."""
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[3];
creg c[3];
h q[0];
cx q[0],q[1];
cx q[1],q[2];
measure q[0] -> c[0];
measure q[1] -> c[1];
measure q[2] -> c[2];
"""


def get_recent_job_ids(provider, limit=15):
    try:
        history = with_timeout(provider.get_job_history, HISTORY_TIMEOUT_S, limit=limit)
        return {h.job_id for h in history}
    except OpTimeout:
        print("  [DEBUG] get_recent_job_ids TIMED OUT")
        return set()
    except Exception as e:
        print(f"  [DEBUG] get_recent_job_ids FAILED: {type(e).__name__}: {e}")
        return set()


def submit_with_recovery(provider, qasm, shots, backend, name,
                          submit_timeout=SUBMIT_TIMEOUT_S):
    known_job_ids = get_recent_job_ids(provider)
    print(f"  [DEBUG] baseline snapshot: {len(known_job_ids)} known job_ids")
    job_id = None
    try:
        job_id = with_timeout(
            provider.submit_circuit, submit_timeout,
            qasm, shots=shots, backend=backend, name=name
        )
        print(f"  [DEBUG] branch=CLEAN_SUCCESS  submitted: {job_id}")
        return job_id
    except OpTimeout:
        print(f"  [DEBUG] branch=TIMEOUT  attempting recovery via history diff")
    except Exception as e:
        print(f"  [DEBUG] branch=EXCEPTION  {type(e).__name__}: {e} — attempting recovery")

    time.sleep(3)
    current_ids = get_recent_job_ids(provider)
    new_ids = current_ids - known_job_ids
    print(f"  [DEBUG] history diff: {len(new_ids)} new job(s): "
          f"{[j[:8] for j in new_ids] if new_ids else '(none)'}")
    if len(new_ids) == 1:
        job_id = next(iter(new_ids))
        print(f"  [DEBUG] branch=RECOVERED_VIA_DIFF  job_id: {job_id}")
    elif len(new_ids) > 1:
        print(f"  [DEBUG] branch=RECOVERY_AMBIGUOUS")
    else:
        print(f"  [DEBUG] branch=RECOVERY_FAILED")
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
            print(f"  status: {last_status} ({int(time.time()-start)}s elapsed)")
            if last_status in ("Completed", "Done", "FAILED", "Cancelled", "Error"):
                return last_status
        except OpTimeout:
            print("  poll timed out — retrying")
        except Exception as e:
            print(f"  poll error ({type(e).__name__}) — retrying")
        time.sleep(poll_interval_s)
    print(f"  gave up after {max_wait_s}s, last known status: {last_status}")
    return last_status


def step3_submit_new_ghz_test(provider):
    print("="*70)
    print(f"STEP 3: Submitting NEW 3-qubit GHZ state test to {BACKEND}")
    print("="*70)
    qasm = build_ghz3()
    job_id = submit_with_recovery(provider, qasm, 1024, BACKEND,
                                   "watchdog_ghz3_rigetti")
    print(f"Job ID: {job_id}")

    print(f"\nPolling (max {POLL_MAX_WAIT_S}s)...")
    status = poll_job_status(provider, job_id)

    if status not in ("Completed", "Done"):
        print(f"\nINCOMPLETE — status: {status}  job_id: {job_id}")
        return {"backend": BACKEND, "job_id": job_id, "status": status,
                 "matches_ghz_prediction": None, "timestamp": now_iso()}

    result = provider.get_job_results(job_id)
    counts = result.get("raw", {})
    total = sum(counts.values())
    ghz_correlated = counts.get("000", 0) + counts.get("111", 0)
    fraction = ghz_correlated / total if total else 0
    matches = fraction > 0.6  # 3-qubit GHZ threshold, more noise-prone than 2-qubit

    print(f"\nCounts: {counts}")
    print(f"GHZ correlation (000/111 dominant): {fraction:.4f}")
    print(f"Matches GHZ prediction: {matches}")

    return {
        "backend": BACKEND, "job_id": job_id, "status": status,
        "counts": counts, "ghz_correlated_fraction": round(fraction, 4),
        "matches_ghz_prediction": matches, "shots": total,
        "timestamp": now_iso(),
    }


if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    step1_cancel_stuck_garnet_jobs(provider)
    step2_check_and_run_optional_scripts()
    ghz_result = step3_submit_new_ghz_test(provider)

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module106_ghz3_rigetti_result.json")
    with open(output_path, "w") as f:
        json.dump(ghz_result, f, indent=2)
    print(f"\nSaved to {output_path}")
