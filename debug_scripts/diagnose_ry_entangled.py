"""
Isolates the CHSH bug with a maximally-distinguishing test:
h;cx;ry(pi) on the SECOND qubit of an entangled pair, right before
measurement — the same structural position as the CHSH circuits.

Ideal prediction: starting Bell state (|00>+|11>)/sqrt(2), applying
ry(pi) to q1 should transform it to ~(|01>-|10>)/sqrt(2), meaning
measurement should land ALMOST ENTIRELY in '01'/'10', with '00'/'11'
near zero.

If real hardware instead stays mostly in '00'/'11' (like the CHSH
results did), that proves ry() on an entangled qubit right before
measurement is not taking effect as expected in this specific
circuit position — even though the isolated single-qubit ry(pi) test
worked perfectly. This pinpoints whether the bug is rotation-after-
entanglement specifically, or something about the CHSH angles chosen.
"""
import time
from quantum_providers import get_provider

provider = get_provider()
print(f"Provider: {provider.provider_name}\n")

qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
ry(3.14159265358979) q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""

print("--- Submitting entangled ry(pi) diagnostic (512 shots) ---")
job_id = provider.submit_circuit(qasm, shots=512, backend="iqm:garnet",
                                  name="watchdog_diagnose_ry_entangled")
print(f"Job ID: {job_id}")
print("Waiting 25s...")
time.sleep(25)

job = provider._scheduler.get_job(job_id)
print(f"Status: {job.status}")

result = provider.get_job_results(job_id)
counts = result.get("raw", {})
total = sum(counts.values())
print(f"\nCounts: {counts}")

p00 = counts.get("00", 0) / total if total else 0
p11 = counts.get("11", 0) / total if total else 0
p01 = counts.get("01", 0) / total if total else 0
p10 = counts.get("10", 0) / total if total else 0

print(f"00: {p00*100:.1f}%   11: {p11*100:.1f}%   (expected: ~0%)")
print(f"01: {p01*100:.1f}%   10: {p10*100:.1f}%   (expected: ~50% each)")
print()

if (p01 + p10) > 0.7:
    print("=== DIAGNOSIS: ry() works correctly on entangled qubits ===")
    print("The CHSH bug is specific to the chosen angles or the")
    print("correlation computation — not a general rotation failure.")
elif (p00 + p11) > 0.7:
    print("=== DIAGNOSIS: ry() is NOT taking effect after entanglement ===")
    print("This confirms the CHSH bug: rotations applied to an already-")
    print("entangled qubit right before measurement are not having the")
    print("expected effect, even though isolated single-qubit ry() works.")
    print("Likely cause: transpiler optimization collapsing/reordering")
    print("gates around the entangling CX in a way that loses the")
    print("intended measurement-basis rotation.")
else:
    print("=== DIAGNOSIS: Mixed/inconclusive result ===")
