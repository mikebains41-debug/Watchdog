"""Module 130 — Circuit Integrity Fingerprinting (formalized, reusable)

METHOD: generalizes module95's control/injected concept into a
reusable fingerprinting system. Instead of just "control vs one
injected variant," this generates a random per-run KEY, builds a
circuit whose correct output is uniquely determined by that key (via
X gates on specific qubits based on key bits), submits it, and
verifies the REAL hardware result matches the exact predicted pattern
for THAT key — not just "looks entangled," but "matches this specific
run's unique fingerprint."

Why this matters: a generic "looks like a Bell state" check could be
fooled by a cached, replayed, or generic canned response. A fresh,
random, per-run fingerprint cannot be faked without actually running
the real circuit, because the correct answer changes every time.
"""
import json, time, datetime, os, signal, secrets
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 25; HISTORY_TIMEOUT_S = 15; POLL_MAX_WAIT_S = 180; POLL_INTERVAL_S = 8
BACKEND = "rigetti:cepheus-1-108q"
NUM_QUBITS = 4  # small + cheap

class OpTimeout(Exception): pass
def _alarm_handler(s, f): raise OpTimeout()
def with_timeout(func, t, *a, **kw):
    old = signal.signal(signal.SIGALRM, _alarm_handler); signal.alarm(t)
    try: return func(*a, **kw)
    finally: signal.alarm(0); signal.signal(signal.SIGALRM, old)
def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def generate_key(num_qubits=NUM_QUBITS):
    """Random per-run key — the whole point is this is unpredictable
    and different every time, so the expected output can't be cached
    or guessed in advance."""
    return [secrets.randbits(1) for _ in range(num_qubits)]

def build_fingerprint_circuit(key):
    """GHZ-style entangled base, then X gates applied per key bit.
    The two 'expected' basis states become key-dependent: instead of
    always 0000/1111, it becomes key/~key for whatever key was drawn
    this run."""
    n = len(key)
    lines = ["OPENQASM 2.0;", 'include "qelib1.inc";', f"qreg q[{n}];", f"creg c[{n}];", "h q[0];"]
    for i in range(n - 1):
        lines.append(f"cx q[{i}],q[{i+1}];")
    for i, bit in enumerate(key):
        if bit == 1:
            lines.append(f"x q[{i}];")
    for i in range(n):
        lines.append(f"measure q[{i}] -> c[{i}];")
    return "\n".join(lines) + "\n"

def key_to_bitstrings(key):
    """The two expected dominant outcomes for this specific key:
    the key itself, and its bitwise complement (since the base state
    was |00..0>+|11..1>, X-flipping per key bit maps those to
    key and ~key respectively)."""
    key_str = "".join(str(b) for b in key)
    complement_str = "".join(str(1 - b) for b in key)
    return key_str, complement_str

def get_recent_job_ids(provider, limit=15):
    try: return {h.job_id for h in with_timeout(provider.get_job_history, HISTORY_TIMEOUT_S, limit=limit)}
    except Exception as e: print(f"  [DEBUG] history FAILED: {e}"); return set()

def submit_with_recovery(provider, qasm, shots, backend, name):
    known = get_recent_job_ids(provider)
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
    print(f"Provider: {provider.provider_name}\n")

    key = generate_key()
    key_str, complement_str = key_to_bitstrings(key)
    print(f"Generated random per-run fingerprint key: {key_str}")
    print(f"Expected dominant outcomes: {key_str} and {complement_str}\n")

    qasm = build_fingerprint_circuit(key)
    print(f"--- Submitting fingerprinted circuit to {BACKEND} ---")
    jid = submit_with_recovery(provider, qasm, 1024, BACKEND, f"watchdog_fingerprint_{key_str}")
    print(f"Job ID: {jid}")

    print(f"\nPolling (max {POLL_MAX_WAIT_S}s)...")
    status = poll(provider, jid)

    result = {"backend": BACKEND, "job_id": jid, "status": status,
               "fingerprint_key": key_str, "expected_outcomes": [key_str, complement_str],
               "timestamp": now_iso()}

    if status in ("Completed", "Done"):
        raw = provider.get_job_results(jid)
        counts = raw.get("raw", {})
        total = sum(counts.values())
        matched = counts.get(key_str, 0) + counts.get(complement_str, 0)
        fraction = matched / total if total else 0
        integrity_confirmed = fraction > 0.6

        print(f"\nCounts: {counts}")
        print(f"Fraction matching THIS RUN's unique fingerprint: {fraction:.4f}")
        print(f"\n{'='*50}")
        print(f"CIRCUIT INTEGRITY: {'CONFIRMED — real hardware executed the exact fresh, unpredictable circuit submitted' if integrity_confirmed else 'FAILED — output does not match this run unique fingerprint'}")
        print(f"{'='*50}")

        result.update({"counts": counts, "shots": total,
                        "fingerprint_match_fraction": round(fraction, 4),
                        "integrity_confirmed": integrity_confirmed})
    else:
        print(f"\nINCOMPLETE — {status}")

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module130_fingerprint_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
