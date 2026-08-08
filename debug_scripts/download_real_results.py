"""
Downloads the REAL measurement results from the Bell state job.
This is the strongest possible proof-of-product evidence: actual
quantum measurement counts from real IQM Garnet hardware.
"""
from quantum_providers import get_provider
import json

provider = get_provider()

jobs = {
    "bell_state":    "a209911f-3f01-40da-892b-1892b3e8f6dd",
    "ghz_state":      "e3bf369d-bd93-42c8-9d9b-840e32ff355c",
    "single_qubit":   "69d726ae-f372-4d64-8bd4-9f15d7d6b6f1",
}

for name, job_id in jobs.items():
    print(f"\n{'='*50}")
    print(f"=== {name} ({job_id}) ===")
    print('='*50)
    try:
        result = provider.get_job_results(job_id)
        print(json.dumps(result, indent=2)[:2000])
    except Exception as e:
        print(f"FAILED: {e}")
