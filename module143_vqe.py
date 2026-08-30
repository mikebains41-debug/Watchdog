"""Module 143 — VQE Molecular Ground-State Tamper Detection (H2 molecule)
Real algorithm class used for drug discovery / materials science —
the largest single vertical in the market research ($250B+ estimate).
VQE finds a molecule's ground-state energy; here we run a minimal H2
ansatz on real Rigetti hardware with control vs corrupted parameters.
"""
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

def build_h2_ansatz(theta):
    return f"""OPENQASM 2.0;
include "qelib1.inc";
qreg q[2]; creg c[2];
x q[0];
ry({theta}) q[1];
cx q[1],q[0];
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

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")
    theta_correct = math.pi / 4
    theta_corrupted = math.pi / 2

    control_qasm = build_h2_ansatz(theta_correct)
    injected_qasm = build_h2_ansatz(theta_corrupted)

    print("--- Submitting CONTROL VQE ansatz ---")
    control_jid, known = submit_with_recovery(provider, control_qasm, 2048, BACKEND, "watchdog_vqe_control")
    print(f"Control: {control_jid}")

    print("\n--- Submitting INJECTED VQE ansatz ---")
    injected_jid, known = submit_with_recovery(provider, injected_qasm, 2048, BACKEND, "watchdog_vqe_injected", known)
    print(f"Injected: {injected_jid}")

    print("\nPolling...")
    print("Control:"); control_status = poll(provider, control_jid)
    print("Injected:"); injected_status = poll(provider, injected_jid)

    result = {"backend": BACKEND, "control_job_id": control_jid, "injected_job_id": injected_jid,
               "control_status": control_status, "injected_status": injected_status,
               "theta_correct": theta_correct, "theta_corrupted": theta_corrupted,
               "algorithm": "VQE H2 minimal ansatz",
               "industry_relevance": "VQE is the real algorithm class for molecular simulation / drug discovery",
               "timestamp": now_iso()}

    if control_status in ("Completed","Done") and injected_status in ("Completed","Done"):
        cc = provider.get_job_results(control_jid).get("raw", {})
        ic = provider.get_job_results(injected_jid).get("raw", {})
        print(f"\nControl counts: {cc}")
        print(f"Injected counts: {ic}")
        result.update({"control_counts": cc, "injected_counts": ic})
    else:
        print(f"\nIncomplete: control={control_status}, injected={injected_status}")

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module143_vqe_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
