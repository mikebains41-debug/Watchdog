"""
Additional real circuits to broaden the evidence: a superposition test,
a controlled-phase entanglement variant, and a 4-qubit GHZ to show
scaling. Uses remaining OpenQuantum Spark credit productively.
"""
import time, json
from quantum_providers import get_provider

provider = get_provider()
print(f"Provider: {provider.provider_name}\n")

# W-state — a different 3-qubit entanglement class than GHZ.
# Real physics test: shows the module can characterize different
# entanglement structures, not just one canned example.
w_state_qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[3];
creg c[3];
ry(1.9106332362490184) q[0];
ch q[0],q[1];
ccx q[0],q[1],q[2];
cx q[1],q[0];
cx q[2],q[1];
x q[2];
measure q[0] -> c[0];
measure q[1] -> c[1];
measure q[2] -> c[2];
"""

# 4-qubit GHZ — scaling test beyond the 3-qubit result already captured
ghz4_qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[4];
creg c[4];
h q[0];
cx q[0],q[1];
cx q[1],q[2];
cx q[2],q[3];
measure q[0] -> c[0];
measure q[1] -> c[1];
measure q[2] -> c[2];
measure q[3] -> c[3];
"""

# Deterministic circuit — X gate should read '1' essentially every time.
# A "known-correct answer" test, same principle as module72's use for
# the annealer. This is the sharpest possible correctness check: if a
# real quantum computer flips a qubit and measures it, it MUST read 1.
x_gate_qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[1];
creg c[1];
x q[0];
measure q[0] -> c[0];
"""

jobs_to_submit = [
    ("w_state",      w_state_qasm, 1024),
    ("ghz4_state",   ghz4_qasm,    1024),
    ("x_gate_check", x_gate_qasm,  512),
]

submitted = []
for name, qasm, shots in jobs_to_submit:
    print(f"--- Submitting {name} ({shots} shots) ---")
    try:
        job_id = provider.submit_circuit(qasm, shots=shots,
                                          backend="iqm:garnet",
                                          name=f"watchdog_proof_{name}")
        print(f"Job ID: {job_id}")
        submitted.append((name, job_id))
    except Exception as e:
        print(f"FAILED: {e}")
    time.sleep(2)

print(f"\n=== Submitted {len(submitted)} jobs — waiting 45s ===")
time.sleep(45)

print("\n=== Results ===")
results_summary = {}
for name, jid in submitted:
    try:
        job = provider._scheduler.get_job(jid)
        print(f"\n{name} ({jid}): status={job.status}")
        result = provider.get_job_results(jid)
        counts = result.get("counts") or result.get("raw", {}).get("counts") or result.get("raw", {})
        print(f"  Counts: {counts}")
        results_summary[name] = {"job_id": jid, "status": job.status, "counts": counts}
    except Exception as e:
        print(f"{name}: FAILED - {e}")
        results_summary[name] = {"job_id": jid, "error": str(e)}

with open("more_real_tests_results.json", "w") as f:
    json.dump(results_summary, f, indent=2)
print("\nSaved to more_real_tests_results.json")
