#!/usr/bin/env python3
# Watchdog -- pull ALL pending results: circuit fingerprint, SPAM calibration, RB re-check
# Read-only, no new credits used. Saves both parsed results and raw job output.

import json, sys
from datetime import datetime, timezone
sys.path.insert(0, "/data/data/com.termux/files/home/Watchdog")
from quantum_providers.openquantum_provider import OpenQuantumProvider

FINGERPRINT_JOB = "aa9d5caa-b15c-4aea-8c32-671de5c4ad0d"
FINGERPRINT_MARKER = "10011110"

def pull_job(provider, job_id):
    job = provider._scheduler.get_job(job_id)
    status = getattr(job, "status", None)
    try:
        raw_output = provider._scheduler.download_job_output(job)
    except Exception as e:
        raw_output = {"error": str(e)}
    counts = raw_output if isinstance(raw_output, dict) else {}
    total = sum(v for v in counts.values() if isinstance(v, int)) if counts else 0
    return {"job_id": job_id, "status": str(status), "raw_output": raw_output, "counts": counts, "total_shots": total}

def main():
    provider = OpenQuantumProvider()
    all_results = {"pulled_at": datetime.now(timezone.utc).isoformat()}

    # Circuit fingerprint
    print(json.dumps({"event": "PULLING", "target": "circuit_fingerprint"}))
    fp_result = pull_job(provider, FINGERPRINT_JOB)
    dominant = max(fp_result["counts"], key=fp_result["counts"].get) if fp_result["counts"] else None
    fp_result["marker_submitted"] = FINGERPRINT_MARKER
    fp_result["dominant_measured_bitstring"] = dominant
    fp_result["matches_marker"] = (dominant == FINGERPRINT_MARKER or dominant == FINGERPRINT_MARKER[::-1]) if dominant else None
    all_results["circuit_fingerprint"] = fp_result
    print(json.dumps({"event": "PULLED", "target": "circuit_fingerprint", "matches_marker": fp_result["matches_marker"]}))

    # SPAM calibration -- load job IDs from the earlier submission file
    print(json.dumps({"event": "PULLING", "target": "spam_calibration"}))
    try:
        with open("/data/data/com.termux/files/home/Watchdog-quantum-collab/spam_calibration_submitted.json") as f:
            spam_submitted = json.load(f)
        spam_jobs = spam_submitted.get("jobs", {})
    except Exception as e:
        spam_jobs = {}
        print(json.dumps({"event": "SPAM_JOBS_FILE_MISSING", "error": str(e)}))

    spam_results = {}
    for label, job_id in spam_jobs.items():
        spam_results[label] = pull_job(provider, job_id)
        print(json.dumps({"event": "PULLED", "target": f"spam_{label}", "counts": spam_results[label]["counts"]}))
    all_results["spam_calibration"] = spam_results

    # RB re-check (already have these job IDs)
    print(json.dumps({"event": "PULLING", "target": "rb_v2_recheck"}))
    RB_JOBS = {
        "1": "720159eb-0276-4748-96ae-8e00070fea8e",
        "2": "c1afdb5f-0a87-4720-94a5-a88d7862954d",
        "4": "b0ae4dff-de39-4a79-a308-8c2919cd5134",
        "8": "ad4ae646-1798-4df0-922d-a0f21e4de6d5",
        "16": "8168c662-3b14-433a-85a8-32042d735557",
        "32": "754191db-8458-4500-b2de-cd343d6928ea",
        "64": "06adc2e6-a8f2-4f64-8796-85fb522189df",
    }
    rb_results = {}
    for n, job_id in RB_JOBS.items():
        rb_results[n] = pull_job(provider, job_id)
        print(json.dumps({"event": "PULLED", "target": f"rb_n{n}", "counts": rb_results[n]["counts"]}))
    all_results["randomized_benchmarking"] = rb_results

    outpath = "/data/data/com.termux/files/home/Watchdog-quantum-collab/ALL_PENDING_RESULTS_pulled.json"
    with open(outpath, "w") as f:
        json.dump(all_results, f, indent=2)
    print(json.dumps({"event": "ALL_RESULTS_SAVED", "path": outpath}))

if __name__ == "__main__":
    main()
