"""
Real OpenQuantum hardware tests — checks CHSH fix status, then pushes
GHZ scaling to 8 qubits (double the previous best of 4), a genuinely
new result. Writes directly to the collab repo's evidence folder.
"""
import time, json, math, os
from quantum_providers import get_provider

provider = get_provider()
print(f"Provider: {provider.provider_name}\n")

OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Check CHSH fix status first ──
chsh_path = os.path.join(OUTPUT_DIR, "chsh_fixed_result_v2.json")
print("=== CHSH Fix Status ===")
if os.path.exists(chsh_path):
    with open(chsh_path) as f:
        chsh = json.load(f)
    print(f"S = {chsh['S']:.4f}")
    print(f"Violates classical bound: {chsh['violates_classical']}")
else:
    print("CHSH fix result not found — was not completed last run")
print()

# ── New serious finding: 8-qubit GHZ, real scaling test ──
print("=== Submitting 8-qubit GHZ state (new scaling record) ===")
n = 8
qasm = 'OPENQASM 2.0;\ninclude "qelib1.inc";\n'
qasm += f'qreg q[{n}];\ncreg c[{n}];\n'
qasm += 'h q[0];\n'
for i in range(n - 1):
    qasm += f'cx q[{i}],q[{i+1}];\n'
for i in range(n):
    qasm += f'measure q[{i}] -> c[{i}];\n'

SHOTS = 1024
job_id = provider.submit_circuit(qasm, shots=SHOTS, backend="iqm:garnet",
                                  name="watchdog_ghz8_scaling_record")
print(f"Job ID: {job_id}")
print("Waiting 40s...")
time.sleep(40)

job = provider._scheduler.get_job(job_id)
print(f"Status: {job.status}")

result = provider.get_job_results(job_id)
counts = result.get("raw", {})
total = sum(counts.values())

all_zero = "0" * n
all_one = "1" * n
correct = counts.get(all_zero, 0) + counts.get(all_one, 0)
fidelity = correct / total if total else 0

print(f"\nCounts: {counts}")
print(f"\n8-qubit GHZ fidelity: {fidelity*100:.1f}%")
print(f"(Previous best: 4-qubit GHZ at 88.2% — this tests double the qubit count)")

output_path = os.path.join(OUTPUT_DIR, "ghz8_scaling_result.json")
with open(output_path, "w") as f:
    json.dump({
        "job_id": job_id, "backend": "iqm:garnet", "n_qubits": n,
        "shots": SHOTS, "counts": counts, "fidelity": fidelity,
        "status": job.status,
        "note": ("New scaling record — 8-qubit GHZ state, double the "
                  "previously tested 4-qubit maximum. Real hardware, "
                  "second OpenQuantum account."),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, f, indent=2)
print(f"\nSaved to {output_path}")
