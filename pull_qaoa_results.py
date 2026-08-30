"""Manually compute QAOA solution quality from the 2 completed jobs."""
import json, os
from quantum_providers import get_provider

CONTROL_JID = "06424a75-c494-41b3-8bb1-7fe3f427ae93"
INJECTED_JID = "ae447d2a-52f9-4d53-afc0-4a5c5f902a52"
EDGES = [(0, 1), (1, 2), (0, 2)]

def cut_value(bitstring):
    return sum(1 for (a, b) in EDGES if bitstring[a] != bitstring[b])

provider = get_provider()

control_result = provider.get_job_results(CONTROL_JID)
injected_result = provider.get_job_results(INJECTED_JID)

control_counts = control_result.get("raw", {})
injected_counts = injected_result.get("raw", {})

control_total = sum(control_counts.values())
injected_total = sum(injected_counts.values())

control_avg_cut = sum(cut_value(bs) * n for bs, n in control_counts.items()) / control_total
injected_avg_cut = sum(cut_value(bs) * n for bs, n in injected_counts.items()) / injected_total

print(f"Control counts: {control_counts}")
print(f"Control average cut value: {control_avg_cut:.4f} (max possible: 2)\n")

print(f"Injected counts: {injected_counts}")
print(f"Injected average cut value: {injected_avg_cut:.4f} (max possible: 2)\n")

degradation = control_avg_cut - injected_avg_cut
tamper_detected = degradation > 0.05

print("="*60)
print(f"Solution quality degradation from parameter corruption: {degradation:.4f}")
print(f"TAMPER DETECTABLE VIA SOLUTION QUALITY: {tamper_detected}")
print("="*60)

result = {
    "backend": "rigetti:cepheus-1-108q", "control_job_id": CONTROL_JID, "injected_job_id": INJECTED_JID,
    "algorithm": "QAOA p=1, Max-Cut, triangle graph",
    "industry_relevance": ("QAOA is the algorithm class actually used for portfolio "
                             "optimization (finance), routing (logistics), and grid "
                             "balancing (energy) on real quantum hardware."),
    "control_counts": control_counts, "injected_counts": injected_counts,
    "control_avg_cut_value": round(control_avg_cut, 4),
    "injected_avg_cut_value": round(injected_avg_cut, 4),
    "degradation": round(degradation, 4),
    "tamper_detected_via_solution_quality": tamper_detected,
}

OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)
with open(os.path.join(OUTPUT_DIR, "module142_qaoa_integrity_result.json"), "w") as f:
    json.dump(result, f, indent=2)
print("\nSaved.")
