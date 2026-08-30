"""Module 145 — Physical Crosstalk / Shared-Hardware Interference Test

BLACK HAT SCENARIO: a malicious co-tenant on the same shared 108-qubit
chip deliberately floods it with large, noisy circuits at the same
time your real job runs, hoping to degrade YOUR result quality via
physical crosstalk — a denial-of-quality attack that doesn't touch
your data or account at all, just shares the same physical hardware.

METHOD: submits a large, deliberately "noisy" 16-qubit circuit
(simulating a busy/malicious neighbor) IMMEDIATELY followed by a small
reference Bell-state circuit (our real measurement). Compares that
reference circuit's fidelity against tonight's already-established
clean baseline (~0.91 average from 11 real Bell-state runs). If the
reference circuit's fidelity is measurably worse when run right after
a "noisy neighbor," that's real evidence of physical multi-tenant
interference — a genuine hardware-level security question almost
nobody tests.

BASELINE: 0.9070-0.9113 average across 11 clean Bell-state runs
tonight (see diamond_hunt_corrected result).
"""
import json, time, datetime, os, signal
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 25; HISTORY_TIMEOUT_S = 15; POLL_MAX_WAIT_S = 180; POLL_INTERVAL_S = 8
BACKEND = "rigetti:cepheus-1-108q"
BASELINE_FIDELITY = 0.9091  # average of tonight's 11 clean Bell-state runs

class OpTimeout(Exception): pass
def _alarm_handler(s, f): raise OpTimeout()
def with_timeout(func, t, *a, **kw):
    old = signal.signal(signal.SIGALRM, _alarm_handler); signal.alarm(t)
    try: return func(*a, **kw)
    finally: signal.alarm(0); signal.signal(signal.SIGALRM, old)
def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def build_noisy_neighbor():
    """Large, dense 16-qubit circuit — simulates a busy/malicious
    co-tenant hammering the shared chip."""
    lines = ["OPENQASM 2.0;", 'include "qelib1.inc";', "qreg q[16];", "creg c[16];"]
    for layer in range(4):
        for i in range(16):
            lines.append(f"h q[{i}];")
        for i in range(15):
            lines.append(f"cx q[{i}],q[{i+1}];")
    for i in range(16):
        lines.append(f"measure q[{i}] -> c[{i}];")
    return "\n".join(lines) + "\n"

def build_reference_bell():
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2]; creg c[2];
h q[0]; cx q[0],q[1];
measure q[0] -> c[0]; measure q[1] -> c[1];
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
    time.sleep(2)
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

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")
    print(f"Baseline clean fidelity (tonight, 11 real runs): {BASELINE_FIDELITY:.4f}\n")

    noisy_qasm = build_noisy_neighbor()
    ref_qasm = build_reference_bell()

    print("--- Submitting NOISY NEIGHBOR circuit (simulated busy co-tenant) ---")
    noisy_jid, known = submit_with_recovery(provider, noisy_qasm, 4096, BACKEND, "watchdog_noisy_neighbor")
    print(f"Noisy neighbor job: {noisy_jid}")

    print("\n--- IMMEDIATELY submitting REFERENCE Bell state (our real measurement) ---")
    ref_jid, known = submit_with_recovery(provider, ref_qasm, 2048, BACKEND, "watchdog_crosstalk_reference", known)
    print(f"Reference job: {ref_jid}")

    print("\nPolling reference job (the one that matters)...")
    ref_status = poll(provider, ref_jid)

    result = {"backend": BACKEND, "noisy_neighbor_job_id": noisy_jid, "reference_job_id": ref_jid,
               "reference_status": ref_status, "baseline_fidelity": BASELINE_FIDELITY,
               "scenario": "Tests whether a large concurrent 'noisy neighbor' circuit on shared "
                           "hardware degrades a small reference circuit's fidelity — a physical "
                           "multi-tenant interference / denial-of-quality question.",
               "timestamp": now_iso()}

    if ref_status in ("Completed", "Done"):
        raw = provider.get_job_results(ref_jid)
        counts = raw.get("raw", {})
        total = sum(counts.values())
        fidelity = (counts.get("00",0) + counts.get("11",0)) / total if total else 0
        deviation = fidelity - BASELINE_FIDELITY

        print(f"\nReference counts: {counts}")
        print(f"Reference fidelity (right after noisy neighbor): {fidelity:.4f}")
        print(f"Baseline (clean conditions): {BASELINE_FIDELITY:.4f}")
        print(f"Deviation: {deviation:+.4f}")

        meaningful_degradation = deviation < -0.03

        print(f"\n{'='*60}")
        if meaningful_degradation:
            print(f"REAL FINDING: fidelity measurably WORSE after noisy neighbor — "
                  f"possible physical crosstalk / multi-tenant interference detected")
        else:
            print(f"NO meaningful degradation — reference fidelity consistent with "
                  f"clean baseline despite concurrent noisy neighbor circuit")
        print(f"{'='*60}")

        result.update({"reference_counts": counts, "reference_fidelity": round(fidelity, 4),
                        "deviation_from_baseline": round(deviation, 4),
                        "meaningful_degradation_detected": meaningful_degradation})
    else:
        print(f"\nIncomplete — reference status: {ref_status}")

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module145_crosstalk_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
