#!/usr/bin/env python3
import json, sys
from datetime import datetime, timezone
sys.path.insert(0, "/data/data/com.termux/files/home/Watchdog")
from quantum_providers.openquantum_provider import OpenQuantumProvider

JOBS = {
    "1": "720159eb-0276-4748-96ae-8e00070fea8e",
    "2": "c1afdb5f-0a87-4720-94a5-a88d7862954d",
    "4": "b0ae4dff-de39-4a79-a308-8c2919cd5134",
    "8": "ad4ae646-1798-4df0-922d-a0f21e4de6d5",
    "16": "8168c662-3b14-433a-85a8-32042d735557",
    "32": "754191db-8458-4500-b2de-cd343d6928ea",
    "64": "06adc2e6-a8f2-4f64-8796-85fb522189df",
}

def main():
    provider = OpenQuantumProvider()
    results = {}
    for n, job_id in JOBS.items():
        try:
            job = provider._scheduler.get_job(job_id)
            counts = provider._scheduler.download_job_output(job)
            if not isinstance(counts, dict):
                counts = {}
            total = sum(counts.values()) if counts else 0
            zero_count = counts.get("0", 0)
            survival_prob = (zero_count / total) if total > 0 else None
            results[n] = {"job_id": job_id, "counts": counts, "total_shots": total, "survival_probability": survival_prob}
            print(json.dumps({"event": "RESULT_PULLED", "n": n, "survival_probability": survival_prob}))
        except Exception as e:
            results[n] = {"job_id": job_id, "error": str(e)}
            print(json.dumps({"event": "RESULT_PULL_FAILED", "n": n, "error": str(e)}))

    output = {
        "module": "randomized_benchmarking_v2_results",
        "backend": "rigetti:cepheus-1-108q",
        "results_by_sequence_length": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    outpath = "/data/data/com.termux/files/home/Watchdog-quantum-collab/rb_rigetti_v2_RESULTS.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
