"""Module 113 — Long-Duration Stability Monitor (Rigetti)
Submits a Bell state every 5 minutes for up to 1 hour, logs real
fidelity over time. Designed to run in the BACKGROUND via nohup —
this genuinely takes an hour of real wall-clock time; there is no
way to shortcut that and still get real temporal data.

Usage:
  nohup python3 module113.py > module113_output.log 2>&1 &
  (then check back later — do NOT watch it live with tail -f, same
   mistake that caused the tail -f freeze earlier tonight)
"""
import json, time, datetime, os, signal
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 25; HISTORY_TIMEOUT_S = 15; POLL_MAX_WAIT_S = 120; POLL_INTERVAL_S = 8
BACKEND = "rigetti:cepheus-1-108q"
INTERVAL_S = 300   # 5 minutes between submissions
DURATION_S = 3600  # 1 hour total

class OpTimeout(Exception): pass
def _alarm_handler(s, f): raise OpTimeout()
def with_timeout(func, t, *a, **kw):
    old = signal.signal(signal.SIGALRM, _alarm_handler); signal.alarm(t)
    try: return func(*a, **kw)
    finally: signal.alarm(0); signal.signal(signal.SIGALRM, old)
def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def build_bell():
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2]; creg c[2];
h q[0]; cx q[0],q[1];
measure q[0]->c[0]; measure q[1]->c[1];
"""

def get_recent_job_ids(provider, limit=15):
    try: return {h.job_id for h in with_timeout(provider.get_job_history, HISTORY_TIMEOUT_S, limit=limit)}
    except Exception: return set()

def submit_with_recovery(provider, qasm, shots, backend, name):
    known = get_recent_job_ids(provider)
    try:
        return with_timeout(provider.submit_circuit, SUBMIT_TIMEOUT_S, qasm, shots=shots, backend=backend, name=name)
    except Exception:
        pass
    time.sleep(3)
    new = get_recent_job_ids(provider) - known
    return next(iter(new)) if len(new) == 1 else None

def poll(provider, jid):
    if jid is None: return "UNKNOWN"
    start = time.time(); last = "UNKNOWN"
    while time.time() - start < POLL_MAX_WAIT_S:
        try:
            j = with_timeout(provider._scheduler.get_job, 15, jid); last = j.status
            if last in ("Completed", "Done", "FAILED", "Cancelled", "Error"): return last
        except Exception: pass
        time.sleep(POLL_INTERVAL_S)
    return last

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}")
    print(f"Starting {DURATION_S//60}-minute stability monitor, "
          f"submitting every {INTERVAL_S//60} minutes\n")

    log = []
    start_time = time.time()
    run_num = 0

    while time.time() - start_time < DURATION_S:
        run_num += 1
        print(f"[{now_iso()}] Run {run_num}: submitting Bell state...")
        qasm = build_bell()
        jid = submit_with_recovery(provider, qasm, 1024, BACKEND, f"watchdog_stability_run{run_num}")
        status = poll(provider, jid)

        entry = {"run": run_num, "job_id": jid, "status": status, "timestamp": now_iso()}
        if status in ("Completed", "Done") and jid:
            try:
                raw = provider.get_job_results(jid)
                counts = raw.get("raw", {})
                total = sum(counts.values())
                fidelity = (counts.get("00",0)+counts.get("11",0))/total if total else 0
                entry.update({"counts": counts, "fidelity": round(fidelity, 4), "shots": total})
                print(f"  Run {run_num}: fidelity={fidelity:.4f}")
            except Exception as e:
                print(f"  Run {run_num}: could not fetch results: {e}")
        else:
            print(f"  Run {run_num}: status={status}")

        log.append(entry)

        # Save progress after EVERY run, not just at the end — so partial
        # data survives even if the process gets killed early
        OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(os.path.join(OUTPUT_DIR, "module113_stability_rigetti_result.json"), "w") as f:
            json.dump({"backend": BACKEND, "runs": log, "interval_s": INTERVAL_S,
                        "duration_s": DURATION_S, "timestamp": now_iso()}, f, indent=2)

        remaining = DURATION_S - (time.time() - start_time)
        if remaining <= 0:
            break
        sleep_time = min(INTERVAL_S, remaining)
        time.sleep(sleep_time)

    print(f"\nMonitoring complete. {len(log)} runs logged.")
    fidelities = [r["fidelity"] for r in log if "fidelity" in r]
    if fidelities:
        print(f"Fidelity range: {min(fidelities):.4f} - {max(fidelities):.4f}")
        print(f"Average: {sum(fidelities)/len(fidelities):.4f}")
