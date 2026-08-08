"""
Tests whether ry(-pi) (NEGATIVE angle) works the same as ry(+pi), which
just succeeded. Every CHSH rotation used ry(-theta) — if negative
angles are silently mishandled by this compiler, that explains why
every CHSH setting collapsed to the raw, unrotated Bell correlation.
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
ry(-3.14159265358979) q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""

print("--- Submitting entangled ry(-pi) diagnostic (512 shots) ---")
job_id = provider.submit_circuit(qasm, shots=512, backend="iqm:garnet",
                                  name="watchdog_diagnose_negative_ry")
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

print(f"00: {p00*100:.1f}%   11: {p11*100:.1f}%   (if working: ~0%, if broken: ~50%)")
print(f"01: {p01*100:.1f}%   10: {p10*100:.1f}%   (if working: ~50% each, if broken: ~0%)")
print()

if (p01 + p10) > 0.7:
    print("=== ry(-pi) WORKS CORRECTLY — negative angles are fine ===")
    print("The CHSH bug is something else entirely.")
elif (p00 + p11) > 0.7:
    print("=== CONFIRMED: ry(-pi) FAILS — negative angles are broken ===")
    print("This is the CHSH bug. Fix: rebuild all four CHSH circuits")
    print("using only POSITIVE rotation angles.")
else:
    print("=== Inconclusive ===")
