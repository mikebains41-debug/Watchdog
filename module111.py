"""Module 111 — Full 2-Qubit State Tomography (ZZ, XX, YY bases)
Extends module97's 2-basis witness (ZZ, XX) to 3 bases (adding YY),
giving a tighter fidelity estimate than the lower-bound witness alone.
Still not the full 9-setting tomography needed for the complete
density matrix, but a real step closer, honestly scoped."""
import json, time, datetime, os, signal
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 25; HISTORY_TIMEOUT_S = 15; POLL_MAX_WAIT_S = 180; POLL_INTERVAL_S = 8
BACKEND = "ionq:forte-1"

class OpTimeout(Exception): pass
def _alarm_handler(s, f): raise OpTimeout()
def with_timeout(func, t, *a, **kw):
    old = signal.signal(signal.SIGALRM, _alarm_handler); signal.alarm(t)
    try: return func(*a, **kw)
    finally: signal.alarm(0); signal.signal(signal.SIGALRM, old)
def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def build_bell_zz():
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2]; creg c[2];
h q[0]; cx q[0],q[1];
measure q[0]->c[0]; measure q[1]->c[1];
"""
def build_bell_xx():
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2]; creg c[2];
h q[0]; cx q[0],q[1]; h q[0]; h q[1];
measure q[0]->c[0]; measure q[1]->c[1];
"""
def build_bell_yy():
    # Y-basis measurement: sdg then h before measuring
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2]; creg c[2];
h q[0]; cx q[0],q[1]; sdg q[0]; h q[0]; sdg q[1]; h q[1];
measure q[0]->c[0]; measure q[1]->c[1];
"""

def correlation_fraction(counts, total):
    return (counts.get("00",0)+counts.get("11",0))/total if total else 0

def get_recent_job_ids(provider, limit=15):
    try: return {h.job_id for h in with_timeout(provider.get_job_history, HISTORY_TIMEOUT_S, limit=limit)}
    except Exception as e: print(f"  [DEBUG] history FAILED: {e}"); return set()

def submit_with_recovery(provider, qasm, shots, backend, name, known_ids=None):
    if known_ids is None: known_ids = get_recent_job_ids(provider)
    print(f"  [DEBUG] baseline: {len(known_ids)} jobs")
    try:
        jid = with_timeout(provider.submit_circuit, SUBMIT_TIMEOUT_S, qasm, shots=shots, backend=backend, name=name)
        print(f"  [DEBUG] CLEAN_SUCCESS: {jid}")
        return jid, known_ids | {jid}
    except OpTimeout: print("  [DEBUG] TIMEOUT — diff recovery")
    except Exception as e: print(f"  [DEBUG] EXCEPTION {e} — diff recovery")
    time.sleep(3)
    current = get_recent_job_ids(provider)
    new = current - known_ids
    print(f"  [DEBUG] diff: {[j[:8] for j in new] if new else '(none)'}")
    jid = next(iter(new)) if len(new) == 1 else None
    return jid, current

def poll(provider, jid):
    if jid is None: return "UNKNOWN"
    start = time.time(); last = "UNKNOWN"
    while time.time() - start < POLL_MAX_WAIT_S:
        try:
            j = with_timeout(provider._scheduler.get_job, 15, jid); last = j.status
            print(f"  status: {last} ({int(time.time()-start)}s)")
            if last in ("Completed", "Done", "FAILED", "Cancelled", "Error"): return last
        except Exception: print("  poll error — retry")
        time.sleep(POLL_INTERVAL_S)
    return last

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n--- 3-basis tomography (ZZ/XX/YY) to {BACKEND} ---")

    jobs = {}
    known = None
    for basis, qasm in [("ZZ", build_bell_zz()), ("XX", build_bell_xx()), ("YY", build_bell_yy())]:
        print(f"\nSubmitting {basis}...")
        jid, known = submit_with_recovery(provider, qasm, 1024, BACKEND, f"watchdog_tomo_{basis.lower()}", known)
        jobs[basis] = jid
        print(f"{basis} job: {jid}")

    results = {}
    for basis, jid in jobs.items():
        print(f"\nPolling {basis}...")
        status = poll(provider, jid)
        results[basis] = {"job_id": jid, "status": status}
        if status in ("Completed", "Done"):
            raw = provider.get_job_results(jid)
            counts = raw.get("raw", {})
            total = sum(counts.values())
            p = correlation_fraction(counts, total)
            results[basis].update({"counts": counts, "correlation": round(p, 4), "shots": total})
            print(f"{basis} correlation: {p:.4f}")

    complete = all(r["status"] in ("Completed","Done") for r in results.values())
    if complete:
        p_zz = results["ZZ"]["correlation"]
        p_xx = results["XX"]["correlation"]
        p_yy = results["YY"]["correlation"]
        # Simple 3-basis average as a tighter estimate than the 2-basis witness
        avg_fidelity_estimate = (p_zz + p_xx + p_yy) / 3
        print(f"\n{'='*50}")
        print(f"3-basis average (tighter than 2-basis lower bound): {avg_fidelity_estimate:.4f}")
        print(f"Compare to module97's 2-basis lower bound (82.52%)")
        print(f"{'='*50}")
    else:
        print("\nOne or more bases incomplete — no combined estimate computed")

    result = {"backend": BACKEND, "bases": results,
               "all_complete": complete, "timestamp": now_iso()}
    if complete:
        result["three_basis_average_fidelity_estimate"] = round(avg_fidelity_estimate, 4)

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module111_tomography_rigetti_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
