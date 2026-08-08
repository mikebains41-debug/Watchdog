"""
Submits multiple real circuits to OpenQuantum to build genuine job
history — real evidence, not a single data point. Uses the confirmed
working submit_circuit() path.
"""
import time
from quantum_providers import get_provider

provider = get_provider()
print(f"Provider: {provider.provider_name}")

# Bell state — standard 2-qubit entanglement test
bell_qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""

# GHZ state — 3-qubit entanglement, tests wider connectivity
ghz_qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[3];
creg c[3];
h q[0];
cx q[0],q[1];
cx q[1],q[2];
measure q[0] -> c[0];
measure q[1] -> c[1];
measure q[2] -> c[2];
"""

# Single-qubit superposition — simplest possible real job
single_qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[1];
creg c[1];
h q[0];
measure q[0] -> c[0];
"""

jobs_to_submit = [
    ("bell_state", bell_qasm, 1024),
    ("ghz_state", ghz_qasm, 1024),
    ("single_qubit", single_qasm, 512),
]

submitted = []

for name, qasm, shots in jobs_to_submit:
    print(f"\n--- Submitting {name} ({shots} shots) ---")
    try:
        job_id = provider.submit_circuit(qasm, shots=shots,
                                          backend="iqm:garnet",
                                          name=f"watchdog_proof_{name}")
        print(f"Job ID: {job_id}")
        submitted.append((name, job_id))
    except Exception as e:
        print(f"FAILED: {e}")
    time.sleep(2)

print(f"\n=== Submitted {len(submitted)} jobs ===")
for name, jid in submitted:
    print(f"  {name}: {jid}")

print("\nWaiting 30s before checking status...")
time.sleep(30)

print("\n=== Job Status Check ===")
for name, jid in submitted:
    try:
        job = provider._scheduler.get_job(jid)
        print(f"{name}: status={job.status}")
    except Exception as e:
        print(f"{name}: check failed - {e}")

print("\n=== Updated Job History ===")
history = provider.get_job_history(limit=20)
for h in history:
    print(f"  {h}")
