"""
Module 108 — Detuned Bell State: Calibration Drift Sensitivity (Rigetti)

METHOD: submits the same Bell state as module95/97, but with a small
deliberate rotation (rz) added on q0 before the entangling gate. A
perfectly-calibrated system executing this exact rotation should show
a predictable, calculable DROP in correlation as theta increases from
0. Comparing the real hardware result against the theoretical
prediction for that specific angle tests how precisely Rigetti
executes rotation gates — a genuine calibration-sensitivity check,
not just a pass/fail entanglement test.

Theory: for a Bell state with rz(theta) on q0 before the CX gate,
the ZZ-basis correlation follows cos^2(theta/2) — a real, calculable
prediction, not an assumption.
"""
import json, time, datetime, os, math, signal
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 25
HISTORY_TIMEOUT_S = 15
POLL_MAX_WAIT_S = 180
POLL_INTERVAL_S = 8
BACKEND = "rigetti:cepheus-1-108q"
THETA_DEGREES = 30  # deliberate detuning angle


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

def build_detuned_bell(theta_deg):
    theta_rad = math.radians(theta_deg)
    return f"""OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
rz({theta_rad}) q[0];
cx q[0],q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""

def theoretical_correlation(theta_deg):
    theta_rad = math.radians(theta_deg)
    return math.cos(theta_rad / 2) ** 2

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

    theoretical = theoretical_correlation(THETA_DEGREES)
    print(f"Detuning angle: {THETA_DEGREES} degrees")
    print(f"Theoretical predicted correlation: {theoretical:.4f} (cos^2(theta/2))\n")

    print(f"--- Submitting detuned Bell state to {BACKEND} ---")
    qasm = build_detuned_bell(THETA_DEGREES)
    job_id = submit_with_recovery(provider, qasm, 2048, BACKEND, "watchdog_detuned_bell_rigetti")
    print(f"Job ID: {job_id}")

    print(f"\nPolling (max {POLL_MAX_WAIT_S}s)...")
    status = poll_job_status(provider, job_id)

    result = {"backend": BACKEND, "job_id": job_id, "status": status,
               "theta_degrees": THETA_DEGREES, "theoretical_correlation": round(theoretical, 4),
               "timestamp": now_iso()}

    if status in ("Completed", "Done"):
        raw = provider.get_job_results(job_id)
        counts = raw.get("raw", {})
        total = sum(counts.values())
        correlated = counts.get("00", 0) + counts.get("11", 0)
        measured = correlated / total if total else 0
        deviation = abs(measured - theoretical)
        print(f"\nCounts: {counts}")
        print(f"Measured correlation: {measured:.4f}")
        print(f"Theoretical prediction: {theoretical:.4f}")
        print(f"Deviation: {deviation:.4f}")
        print(f"({'Close match — hardware executes rotation accurately' if deviation < 0.1 else 'Notable deviation — possible calibration drift or gate error'})")
        result.update({"counts": counts, "measured_correlation": round(measured, 4),
                        "deviation_from_theory": round(deviation, 4), "shots": total})
    else:
        print(f"\nINCOMPLETE — status: {status}")

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module108_detuned_bell_rigetti_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved.")
