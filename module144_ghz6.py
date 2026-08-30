"""Module 144 — 6-Qubit GHZ Scaling Point (fills gap in decoherence curve)"""
import json, time, datetime, os, signal
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

def build_ghz6():
    lines = ["OPENQASM 2.0;", 'include "qelib1.inc";', "qreg q[6];", "creg c[6];", "h q[0];"]
    for i in range(5): lines.append(f"cx q[{i}],q[{i+1}];")
    for i in range(6): lines.append(f"measure q[{i}] -> c[{i}];")
    return "\n".join(lines) + "\n"

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
    print(f"Provider: {provider.provider_name}\n--- 6-qubit GHZ to {BACKEND} ---")
    qasm = build_ghz6()
    jid = submit_with_recovery(provider, qasm, 4096, BACKEND, "watchdog_ghz6_rigetti")
    print(f"Job ID: {jid}\nPolling...")
    status = poll(provider, jid)
    result = {"backend": BACKEND, "job_id": jid, "status": status, "timestamp": now_iso()}
    if status in ("Completed", "Done"):
        raw = provider.get_job_results(jid); counts = raw.get("raw", {})
        total = sum(counts.values())
        corr = (counts.get("000000",0) + counts.get("111111",0)) / total if total else 0
        print(f"\n6-qubit GHZ correlation: {corr:.4f}  (curve: 3q=79.10%, 6q={corr*100:.2f}%, 8q=18.29%, 16q=0.99%)")
        result.update({"counts": counts, "ghz6_correlated_fraction": round(corr,4), "shots": total})
    else:
        print(f"INCOMPLETE — {status}")
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module144_ghz6_rigetti_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
