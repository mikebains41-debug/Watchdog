"""
Submits the numerically-verified W-state circuit to real OpenQuantum
hardware. Verified locally first via verify_w_state_v2.py — this QASM
is confirmed correct before spending real credit on it.
"""
import time, json
from quantum_providers import get_provider

provider = get_provider()
print(f"Provider: {provider.provider_name}\n")

w_state_verified_qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[3];
creg c[3];
x q[0];
cry(1.9106332362490186) q[0],q[1];
cx q[1],q[0];
cry(1.5707963267948966) q[1],q[2];
cx q[2],q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
measure q[2] -> c[2];
"""

print("--- Submitting verified w_state (1024 shots) ---")
job_id = provider.submit_circuit(w_state_verified_qasm, shots=1024,
                                  backend="iqm:garnet",
                                  name="watchdog_proof_w_state_v2")
print(f"Job ID: {job_id}")

print("\nWaiting 30s...")
time.sleep(30)

job = provider._scheduler.get_job(job_id)
print(f"Status: {job.status}")

result = provider.get_job_results(job_id)
counts = result.get("raw", {})
print(f"Counts: {counts}")

total = sum(counts.values())
print(f"\nTotal shots: {total}")

for state in ("100", "010", "001"):
    pct = (counts.get(state, 0) / total * 100) if total else 0
    print(f"  {state}: {counts.get(state, 0)} ({pct:.1f}%)  <- expected ~33.3%")

other = sum(v for k, v in counts.items() if k not in ("100", "010", "001"))
other_pct = (other / total * 100) if total else 0
print(f"  other (noise): {other} ({other_pct:.1f}%)")

with open("w_state_verified_result.json", "w") as f:
    json.dump({"job_id": job_id, "status": job.status, "counts": counts,
               "verified_locally": True,
               "circuit": w_state_verified_qasm}, f, indent=2)
print("\nSaved to w_state_verified_result.json")
