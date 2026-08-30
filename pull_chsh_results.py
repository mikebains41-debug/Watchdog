"""Manually compute CHSH S value from the 4 completed jobs."""
import json, math, os
from quantum_providers import get_provider

JOBS = {
    "chsh_ab_fixed":   "ebe6f0e8-a537-46fd-b23b-2b421217aebc",
    "chsh_ab2_fixed":  "46fef19a-8daf-46f1-91f5-4a61968a2110",
    "chsh_a2b_fixed":  "9cc28ed3-9b80-471c-989e-717804c26571",
    "chsh_a2b2_fixed": "1a78c638-b04f-4bc7-989f-58b99f0f4960",
}

provider = get_provider()
E_values = {}
all_counts = {}

for name, jid in JOBS.items():
    result = provider.get_job_results(jid)
    counts = result.get("raw", {})
    all_counts[name] = counts
    total = sum(counts.values())
    p00 = counts.get("00", 0) / total if total else 0
    p11 = counts.get("11", 0) / total if total else 0
    p01 = counts.get("01", 0) / total if total else 0
    p10 = counts.get("10", 0) / total if total else 0
    E = p00 + p11 - p01 - p10
    E_values[name] = E
    print(f"{name} ({jid}):")
    print(f"  Counts: {counts}")
    print(f"  E = {E:.4f}\n")

S_real = (E_values["chsh_ab_fixed"] - E_values["chsh_ab2_fixed"]
          + E_values["chsh_a2b_fixed"] + E_values["chsh_a2b2_fixed"])

print("="*50)
print("=== REAL HARDWARE CHSH RESULT (FIXED, RIGETTI) ===")
print("="*50)
print(f"E(a,b)   = {E_values['chsh_ab_fixed']:.4f}")
print(f"E(a,b')  = {E_values['chsh_ab2_fixed']:.4f}")
print(f"E(a',b)  = {E_values['chsh_a2b_fixed']:.4f}")
print(f"E(a',b') = {E_values['chsh_a2b2_fixed']:.4f}")
print(f"\nS (real hardware) = {S_real:.4f}")
print(f"Classical bound: 2.0")
print(f"Quantum (Tsirelson) bound: {2*math.sqrt(2):.4f}")
print(f"\n*** VIOLATES CLASSICAL BOUND: {abs(S_real) > 2.0} ***")

result = {
    "E_values": E_values, "S": S_real, "backend": "rigetti:cepheus-1-108q",
    "classical_bound": 2.0, "quantum_bound": 2*math.sqrt(2),
    "violates_classical": abs(S_real) > 2.0,
    "jobs": JOBS, "all_counts": all_counts, "shots_per_setting": 2048,
    "bug_fixed": "negative ry() angles replaced with positive equivalents (2pi - theta)",
    "reliability_fix": "switched from stuck iqm:garnet to working rigetti:cepheus-1-108q",
}

OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)
with open(os.path.join(OUTPUT_DIR, "chsh_fixed_rigetti_result.json"), "w") as f:
    json.dump(result, f, indent=2)
print("\nSaved to chsh_fixed_rigetti_result.json")
