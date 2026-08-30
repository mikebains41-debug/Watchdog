"""
Module 107 — 8-Qubit GHZ Scaling Test (Rigetti)

METHOD: extends module106's 3-qubit GHZ state to 8 qubits — the exact
scaling test that was attempted and canceled multiple times earlier
tonight on the dead IQM Garnet queue. This is a genuinely new attempt
on the proven-working Rigetti backend.

GHZ state: (|00000000> + |11111111>) / sqrt(2)

Real hardware noise means correlation typically DROPS as qubit count
increases — more qubits means more gates, more time for decoherence.
Comparing this result against module106's 3-qubit result (79.10%
correlation) gives a genuine, real scaling data point.
"""
import json, time, datetime, os, signal
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

def build_ghz8():
    lines = ["OPENQASM 2.0;", 'include "qelib1.inc";',
             "qreg q[8];", "creg c[8];", "h q[0];"]
    for i in range(7):
        lines.append(f"cx q[{i}],q[{i+1}];")
    for i in range(8):
        lines.append(f"measure q[{i}] -> c[{i}];")
    return "\n".join(lines) + "\n"

def get_recent_job_ids(provider, limit=15):
    try:
        history = with_timeout(provider.get_job_history, HISTORY_TIMEOUT_S, limit=limit)
        return {h.job_id for h in history}
    except Exception as e:
        print(f"  [DEBUG] get_recent_job_ids FAILED: {type(e).__name__}: {e}")
        return set()

def submit_with_recovery(provider, qasm, shots, backend, name):
    known_ids = get_recent_job_ids(provider)
    print(f"  [DEBUG] baseline: {len(known_ids)} known job_ids")
    try:
        job_id = with_timeout(provider.submit_circuit, SUBMIT_TIMEOUT_S,
                                qasm, shots=shots, backend=backend, name=name)
        print(f"  [DEBUG] CLEAN_SUCCESS: {job_id}")
        return job_id
    except OpTimeout:
        print(f"  [DEBUG] TIMEOUT — recovering via history diff")
    except Exception as e:
        print(f"  [DEBUG] EXCEPTION {type(e).__name__}: {e} — recovering via history diff")

    time.sleep(3)
    current_ids = get_recent_job_ids(provider)
    new_ids = current_ids - known_ids
    print(f"  [DEBUG] diff: {len(new_ids)} new: {[j[:8] for j in new_ids] if new_ids else '(none)'}")
    if len(new_ids) == 1:
        return next(iter(new_ids))
    return None

def poll_job_status(provider, job_id):
    if job_id is None:
        return "UNKNOWN"
    start = time.time()
    last_status = "UNKNOWN"
    while time.time() - start < POLL_MAX_WAIT_S:
        try:
            job = with_timeout(provider._scheduler.get_job, 15, job_id)
            last_status = job.status
            print(f"  status: {last_status} ({int(time.time()-start)}s)")
            if last_status in ("Completed", "Done", "FAILED", "Cancelled", "Error"):
                return last_status
        except Exception:
            print("  poll error — retrying")
        time.sleep(POLL_INTERVAL_S)
    return last_status

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")
    print(f"--- Submitting 8-qubit GHZ state to {BACKEND} ---")

    qasm = build_ghz8()
    job_id = submit_with_recovery(provider, qasm, 4096, BACKEND, "watchdog_ghz8_rigetti")
    print(f"Job ID: {job_id}")

    print(f"\nPolling (max {POLL_MAX_WAIT_S}s)...")
    status = poll_job_status(provider, job_id)

    result = {"backend": BACKEND, "job_id": job_id, "status": status, "timestamp": now_iso()}

    if status in ("Completed", "Done"):
        raw = provider.get_job_results(job_id)
        counts = raw.get("raw", {})
        total = sum(counts.values())
        ghz_correlated = counts.get("00000000", 0) + counts.get("11111111", 0)
        fraction = ghz_correlated / total if total else 0
        print(f"\nCounts (top states): {dict(sorted(counts.items(), key=lambda x: -x[1])[:5])}")
        print(f"8-qubit GHZ correlation: {fraction:.4f}")
        print(f"Compare to module106's 3-qubit result (79.10%) to see scaling effect")
        result.update({"counts": counts, "ghz8_correlated_fraction": round(fraction, 4),
                        "shots": total, "matches_ghz_prediction": fraction > 0.4})
    else:
        print(f"\nINCOMPLETE — status: {status}")

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module107_ghz8_rigetti_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved.")
