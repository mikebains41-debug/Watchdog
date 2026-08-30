"""
CHSH test, fixed AND made reliable. Two separate fixes combined:

1. PHYSICS FIX (original): every ry(-theta) replaced with the
   mathematically identical ry(2*pi - theta) — same physics (differs
   only by an unobservable global phase), avoiding the confirmed
   negative-angle compiler bug that produced S=1.92 (below the
   classical bound) on the original buggy run.

2. RELIABILITY FIX (new tonight): original script targeted
   iqm:garnet (confirmed stuck all session, 600+ job queue) and used
   raw submit_circuit() with no timeout — would hang indefinitely.
   This version targets rigetti:cepheus-1-108q (the proven-working
   backend all night) and uses the signal.alarm timeout + history-diff
   recovery pattern used successfully across modules 95-136.
"""
import time, json, math, os, signal
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 25; HISTORY_TIMEOUT_S = 15; POLL_MAX_WAIT_S = 180; POLL_INTERVAL_S = 8
BACKEND = "rigetti:cepheus-1-108q"

class OpTimeout(Exception): pass
def _alarm_handler(s, f): raise OpTimeout()
def with_timeout(func, t, *a, **kw):
    old = signal.signal(signal.SIGALRM, _alarm_handler); signal.alarm(t)
    try: return func(*a, **kw)
    finally: signal.alarm(0); signal.signal(signal.SIGALRM, old)

def positive_angle(theta):
    if abs(theta) < 1e-9:
        return 0.0
    return (2 * math.pi - theta) % (2 * math.pi)

a, a2 = 0.0, math.pi / 2
b, b2 = math.radians(225), math.radians(315)

def make_qasm(theta_a, theta_b):
    pos_a = positive_angle(theta_a)
    pos_b = positive_angle(theta_b)
    return f"""OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
ry({pos_a}) q[0];
ry({pos_b}) q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""

def get_recent_job_ids(provider, limit=15):
    try: return {h.job_id for h in with_timeout(provider.get_job_history, HISTORY_TIMEOUT_S, limit=limit)}
    except Exception as e: print(f"  [DEBUG] history FAILED: {e}"); return set()

def submit_with_recovery(provider, qasm, shots, backend, name, known_ids=None):
    if known_ids is None: known_ids = get_recent_job_ids(provider)
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
            print(f"    status: {last} ({int(time.time()-start)}s)")
            if last in ("Completed", "Done", "FAILED", "Cancelled", "Error"): return last
        except Exception: print("    poll error — retry")
        time.sleep(POLL_INTERVAL_S)
    return last

settings = [
    ("chsh_ab_fixed",   a,  b),
    ("chsh_ab2_fixed",  a,  b2),
    ("chsh_a2b_fixed",  a2, b),
    ("chsh_a2b2_fixed", a2, b2),
]
SHOTS = 2048

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")
    print("=== Corrected angles (all positive) ===")
    for name, ta, tb in settings:
        print(f"  {name}: ry({positive_angle(ta):.4f}) q0, ry({positive_angle(tb):.4f}) q1")
    print()

    submitted = []
    known = None
    for name, ta, tb in settings:
        print(f"--- Submitting {name} ({SHOTS} shots) to {BACKEND} ---")
        qasm = make_qasm(ta, tb)
        jid, known = submit_with_recovery(provider, qasm, SHOTS, BACKEND, f"watchdog_{name}", known)
        print(f"Job ID: {jid}")
        submitted.append((name, jid))

    print(f"\n=== Polling all {len(submitted)} jobs (max {POLL_MAX_WAIT_S}s each) ===")
    statuses = {}
    for name, jid in submitted:
        print(f"\nPolling {name}...")
        statuses[name] = poll(provider, jid)

    all_complete = all(s in ("Completed", "Done") for s in statuses.values())
    print(f"\nAll jobs completed: {all_complete}")

    if not all_complete:
        print("\nOne or more jobs incomplete — cannot compute a valid CHSH result.")
        result = {"submitted": dict(submitted), "statuses": statuses,
                   "all_complete": False, "note": "Incomplete, no S value computed"}
    else:
        print("\n=== Results ===")
        E_values = {}
        for name, jid in submitted:
            res = provider.get_job_results(jid)
            counts = res.get("raw", {})
            total = sum(counts.values())
            p00 = counts.get("00", 0) / total if total else 0
            p11 = counts.get("11", 0) / total if total else 0
            p01 = counts.get("01", 0) / total if total else 0
            p10 = counts.get("10", 0) / total if total else 0
            E = p00 + p11 - p01 - p10
            E_values[name] = E
            print(f"\n{name} ({jid}):")
            print(f"  Counts: {counts}")
            print(f"  E = {E:.4f}")

        print("\n" + "="*50)
        print("=== REAL HARDWARE CHSH RESULT (FIXED, ON RIGETTI) ===")
        print("="*50)
        S_real = (E_values["chsh_ab_fixed"] - E_values["chsh_ab2_fixed"]
                  + E_values["chsh_a2b_fixed"] + E_values["chsh_a2b2_fixed"])
        print(f"E(a,b)   = {E_values['chsh_ab_fixed']:.4f}")
        print(f"E(a,b')  = {E_values['chsh_ab2_fixed']:.4f}")
        print(f"E(a',b)  = {E_values['chsh_a2b_fixed']:.4f}")
        print(f"E(a',b') = {E_values['chsh_a2b2_fixed']:.4f}")
        print(f"\nS (real hardware) = {S_real:.4f}")
        print(f"Classical bound: 2.0")
        print(f"Quantum (Tsirelson) bound: {2*math.sqrt(2):.4f}")
        print(f"\n*** VIOLATES CLASSICAL BOUND: {abs(S_real) > 2.0} ***")

        result = {"E_values": E_values, "S": S_real, "backend": BACKEND,
                   "classical_bound": 2.0, "quantum_bound": 2*math.sqrt(2),
                   "violates_classical": abs(S_real) > 2.0,
                   "jobs": dict(submitted), "shots_per_setting": SHOTS, "all_complete": True,
                   "bug_fixed": "negative ry() angles replaced with positive equivalents (2pi - theta)",
                   "reliability_fix": "switched from stuck iqm:garnet to working rigetti:cepheus-1-108q, added timeout+diff-recovery"}

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "chsh_fixed_rigetti_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved.")
