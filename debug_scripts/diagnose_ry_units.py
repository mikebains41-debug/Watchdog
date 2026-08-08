"""
Diagnoses whether this backend's ry() gate expects radians or degrees.

Test: ry(pi) on a qubit starting at |0> MUST flip it fully to |1> if
radians are correctly interpreted (pi radians = 180 degrees = full flip).
If the backend actually expects degrees, ry(pi radians) = ry(3.14159...)
would be interpreted as a 3.14 DEGREE rotation — almost no effect at all,
and the qubit would stay close to |0>.

This single cheap test (1 qubit, small shots) definitively answers the
question before spending any more credit on CHSH.
"""
import time, math
from quantum_providers import get_provider

provider = get_provider()
print(f"Provider: {provider.provider_name}\n")

# If radians: full flip to |1>, ~100%
# If degrees: almost no rotation, stays near |0>
ry_pi_qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[1];
creg c[1];
ry(3.14159265358979) q[0];
measure q[0] -> c[0];
"""

print("--- Submitting ry(pi) diagnostic (256 shots) ---")
job_id = provider.submit_circuit(ry_pi_qasm, shots=256,
                                  backend="iqm:garnet",
                                  name="watchdog_diagnose_ry_units")
print(f"Job ID: {job_id}")
print("Waiting 25s...")
time.sleep(25)

job = provider._scheduler.get_job(job_id)
print(f"Status: {job.status}")

result = provider.get_job_results(job_id)
counts = result.get("raw", {})
total = sum(counts.values())
pct_1 = (counts.get("1", 0) / total * 100) if total else 0
pct_0 = (counts.get("0", 0) / total * 100) if total else 0

print(f"\nCounts: {counts}")
print(f"'0': {pct_0:.1f}%   '1': {pct_1:.1f}%")
print()

if pct_1 > 85:
    print("=== DIAGNOSIS: ry() correctly interprets RADIANS ===")
    print("The CHSH angle bug is something else — needs further investigation.")
elif pct_0 > 85:
    print("=== DIAGNOSIS: ry() EXPECTS DEGREES, not radians ===")
    print("This confirms the CHSH bug: angles like 3.927 (rad) were being")
    print("read as 3.927 DEGREES — almost no rotation at all.")
    print("FIX: convert all angles to degrees before submission, OR pass")
    print("the angle value as if the argument units were degrees.")
else:
    print("=== DIAGNOSIS: INCONCLUSIVE — roughly 50/50 split ===")
    print("Neither pure radians nor pure degrees explanation fits cleanly.")
    print("Needs a second diagnostic with a different angle value.")
