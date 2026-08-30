"""Module 110 — Quantum Volume Style Circuit (5-qubit, 5-layer random)
Submits a fixed pseudo-random circuit of alternating H/CX layers and
measures the output distribution's deviation from ideal uniform
spreading — a simplified proxy for circuit-depth capability, honestly
labeled as simplified, not the full official QV protocol."""
import json, time, datetime, os, math, signal
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 25; HISTORY_TIMEOUT_S = 15; POLL_MAX_WAIT_S = 180; POLL_INTERVAL_S = 8
BACKEND = "rigetti:cepheus-1-108q"

class OpTimeout(Exception): pass
def _alarm_handler(s, f): raise OpTimeout()
def with_timeout(func, t, *a, **kw):
    old = signal.signal(signal.SIGALRM, _alarm_handler); signal.alarm(t)
    try: return func(*a, **kw)
    finally: signal.alarm(0); signal.signal(signal.SIGALRM, old)
def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def build_qv_style():
    """Fixed 5-qubit, 5-layer circuit: alternating H-on-all and a fixed
    CX pattern per layer. Not randomly regenerated per run — a FIXED
    circuit so results are reproducible and comparable run-to-run."""
    lines = ["OPENQASM 2.0;", 'include "qelib1.inc";', "qreg q[5];", "creg c[5];"]
    cx_patterns = [[(0,1),(2,3)], [(1,2),(3,4)], [(0,1),(2,3)], [(1,2),(3,4)], [(0,1),(2,3)]]
    for layer_pairs in cx_patterns:
        for i in range(5):
            lines.append(f"h q[{i}];")
        for a, b in layer_pairs:
            lines.append(f"cx q[{a}],q[{b}];")
    for i in range(5):
        lines.append(f"measure q[{i}] -> c[{i}];")
    return "\n".join(lines) + "\n"

def shannon_entropy(counts, total):
    e = 0.0
    for c in counts.values():
        if c <= 0: continue
        p = c/total; e -= p*math.log2(p)
    return e

def get_recent_job_ids(provider, limit=15):
    try: return {h.job_id for h in with_timeout(provider.get_job_history, HISTORY_TIMEOUT_S, limit=limit)}
    except Exception as e: print(f"  [DEBUG] history FAILED: {e}"); return set()

def submit_with_recovery(provider, qasm, shots, backend, name):
    known = get_recent_job_ids(provider)
    print(f"  [DEBUG] baseline: {len(known)} jobs")
    try:
        jid = with_timeout(provider.submit_circuit, SUBMIT_TIMEOUT_S, qasm, shots=shots, backend=backend, name=name)
        print(f"  [DEBUG] CLEAN_SUCCESS: {jid}"); return jid
    except OpTimeout: print("  [DEBUG] TIMEOUT — diff recovery")
    except Exception as e: print(f"  [DEBUG] EXCEPTION {e} — diff recovery")
    time.sleep(3)
    new = get_recent_job_ids(provider) - known
    print(f"  [DEBUG] diff: {[j[:8] for j in new] if new else '(none)'}")
    return next(iter(new)) if len(new) == 1 else None

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
    print(f"Provider: {provider.provider_name}\n--- QV-style 5q/5-layer circuit to {BACKEND} ---")
    print("(This is a SIMPLIFIED depth-capability proxy, not the official IBM QV protocol)")
    qasm = build_qv_style()
    jid = submit_with_recovery(provider, qasm, 2048, BACKEND, "watchdog_qv_style_rigetti")
    print(f"Job ID: {jid}\nPolling...")
    status = poll(provider, jid)
    result = {"backend": BACKEND, "job_id": jid, "status": status, "timestamp": now_iso(),
               "note": "Simplified QV-style depth-capability proxy, NOT the official IBM Quantum Volume protocol"}
    if status in ("Completed", "Done"):
        raw = provider.get_job_results(jid); counts = raw.get("raw", {})
        total = sum(counts.values())
        n_states_seen = len(counts)
        max_entropy = 5  # 5 qubits, log2(32) = 5
        measured_entropy = shannon_entropy(counts, total)
        print(f"\nStates seen: {n_states_seen}/32 possible")
        print(f"Measured output entropy: {measured_entropy:.4f} / {max_entropy} bits max")
        print(f"(Higher entropy + more states seen suggests less collapse to a narrow subset — "
              f"a rough proxy for circuit fidelity at this depth)")
        result.update({"counts": counts, "shots": total, "states_seen": n_states_seen,
                        "measured_entropy_bits": round(measured_entropy, 4)})
    else:
        print(f"INCOMPLETE — {status}")
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module110_qv_style_rigetti_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
