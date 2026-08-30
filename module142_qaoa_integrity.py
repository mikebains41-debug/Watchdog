"""Module 142 — QAOA Optimization Circuit Integrity Test (industry-relevant)

WHY THIS ONE: QAOA (Quantum Approximate Optimization Algorithm) is the
actual algorithm class real industries would run on quantum hardware
for combinatorial optimization — portfolio optimization (finance),
routing (logistics), grid balancing (energy). This is not a claim that
Watchdog "tested finance" or "tested logistics" — it is a real,
honest bridge: the SAME algorithm family those industries would use,
with Watchdog's tamper-detection method (proven on Bell states in
module95) applied to it for the first time.

METHOD: Max-Cut on a 3-node triangle graph — the canonical small QAOA
benchmark problem. Submits:
  1. CONTROL: correctly-parameterized QAOA circuit (optimal known
     angles for this specific small graph)
  2. INJECTED: same circuit with one deliberately corrupted parameter
     (a wrong gamma angle)

A correctly-executed QAOA circuit should show a measurably higher
probability of landing on an optimal cut than a circuit with corrupted
parameters — this is a REAL, physically meaningful difference, not
just "different bitstring," because QAOA's whole point is that better
parameters produce better (more concentrated) solution distributions.
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

# Triangle graph (3 nodes, edges 0-1, 1-2, 0-2) — canonical small Max-Cut
# problem. Optimal cut value known exactly for this graph (any single
# node vs the other two = cut value 2, the maximum possible).
EDGES = [(0, 1), (1, 2), (0, 2)]

def build_qaoa_circuit(gamma, beta, corrupted=False):
    """p=1 QAOA for triangle Max-Cut. gamma is the problem-Hamiltonian
    angle, beta is the mixer angle. 'corrupted' flips gamma's sign —
    a real, physically meaningful parameter corruption, not just noise."""
    g = -gamma if corrupted else gamma
    lines = ["OPENQASM 2.0;", 'include "qelib1.inc";', "qreg q[3];", "creg c[3];"]
    for i in range(3):
        lines.append(f"h q[{i}];")
    for (a, b) in EDGES:
        lines.append(f"cx q[{a}],q[{b}];")
        lines.append(f"rz({g}) q[{b}];")
        lines.append(f"cx q[{a}],q[{b}];")
    for i in range(3):
        lines.append(f"rx({2*beta}) q[{i}];")
    for i in range(3):
        lines.append(f"measure q[{i}] -> c[{i}];")
    return "\n".join(lines) + "\n"

def cut_value(bitstring):
    """How many edges are 'cut' (endpoints differ) for this assignment."""
    return sum(1 for (a, b) in EDGES if bitstring[a] != bitstring[b])

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
    print("QAOA Max-Cut on triangle graph (industry-relevant: same algorithm")
    print("class used for portfolio optimization / logistics routing / grid balancing)\n")

    gamma, beta = math.pi / 4, math.pi / 8  # reasonable p=1 angles for triangle

    control_qasm = build_qaoa_circuit(gamma, beta, corrupted=False)
    injected_qasm = build_qaoa_circuit(gamma, beta, corrupted=True)

    print("--- Submitting CONTROL (correct QAOA parameters) ---")
    control_jid, known = submit_with_recovery(provider, control_qasm, 2048, BACKEND, "watchdog_qaoa_control")
    print(f"Control job: {control_jid}")

    print("\n--- Submitting INJECTED (corrupted gamma parameter) ---")
    injected_jid, known = submit_with_recovery(provider, injected_qasm, 2048, BACKEND, "watchdog_qaoa_injected", known)
    print(f"Injected job: {injected_jid}")

    print("\nPolling both...")
    print("Control:")
    control_status = poll(provider, control_jid)
    print("Injected:")
    injected_status = poll(provider, injected_jid)

    result = {"backend": BACKEND, "control_job_id": control_jid, "injected_job_id": injected_jid,
               "control_status": control_status, "injected_status": injected_status,
               "gamma": gamma, "beta": beta,
               "algorithm": "QAOA p=1, Max-Cut, triangle graph",
               "industry_relevance": ("QAOA is the algorithm class actually used for portfolio "
                                        "optimization (finance), routing (logistics), and grid "
                                        "balancing (energy) on real quantum hardware."),
               "timestamp": now_iso()}

    if control_status in ("Completed", "Done") and injected_status in ("Completed", "Done"):
        control_counts = provider.get_job_results(control_jid).get("raw", {})
        injected_counts = provider.get_job_results(injected_jid).get("raw", {})

        control_total = sum(control_counts.values())
        injected_total = sum(injected_counts.values())

        control_avg_cut = sum(cut_value(bs) * n for bs, n in control_counts.items()) / control_total
        injected_avg_cut = sum(cut_value(bs) * n for bs, n in injected_counts.items()) / injected_total

        print(f"\nControl counts: {control_counts}")
        print(f"Control average cut value: {control_avg_cut:.4f} (max possible: 2)")
        print(f"\nInjected counts: {injected_counts}")
        print(f"Injected average cut value: {injected_avg_cut:.4f} (max possible: 2)")

        degradation = control_avg_cut - injected_avg_cut
        tamper_detected = degradation > 0.05  # meaningfully worse solution quality

        print(f"\n{'='*60}")
        print(f"Solution quality degradation from parameter corruption: {degradation:.4f}")
        print(f"TAMPER DETECTABLE VIA SOLUTION QUALITY: {tamper_detected}")
        print(f"{'='*60}")

        result.update({
            "control_counts": control_counts, "injected_counts": injected_counts,
            "control_avg_cut_value": round(control_avg_cut, 4),
            "injected_avg_cut_value": round(injected_avg_cut, 4),
            "degradation": round(degradation, 4),
            "tamper_detected_via_solution_quality": tamper_detected,
        })
    else:
        print(f"\nIncomplete — control: {control_status}, injected: {injected_status}")

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module142_qaoa_integrity_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
