"""
diagnose_all_jobs.py — fixes the 0.0-fidelity bug from the previous
puller (which only checked for 2-character "00"/"11" keys, giving
false zeros for every multi-qubit job like GHZ8, GHZ16, and QRNG).

This version auto-detects the actual bitstring length per job and
computes the correct all-zeros/all-ones correlated fraction for ANY
qubit count. It also prints full raw counts for every job so any
unidentified job ID can be manually matched to what it actually was.
"""
import json
import datetime
import os
from quantum_providers import get_provider

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def correct_correlation(counts):
    """Auto-detects bitstring length from the counts dict itself and
    computes the fraction landing on all-zeros or all-ones — works
    correctly regardless of qubit count (2, 3, 8, 16, whatever)."""
    if not counts:
        return None, 0, None
    total = sum(counts.values())
    if total == 0:
        return None, 0, None
    key_lengths = {len(k) for k in counts.keys()}
    if len(key_lengths) != 1:
        return None, total, f"inconsistent key lengths: {key_lengths}"
    n = key_lengths.pop()
    all_zeros = "0" * n
    all_ones = "1" * n
    correlated = counts.get(all_zeros, 0) + counts.get(all_ones, 0)
    return correlated / total, total, n

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    history = provider.get_job_history(limit=50)
    print(f"Fetched {len(history)} jobs\n")

    results = []
    for h in history:
        status = h.status
        job_id = h.job_id
        if status not in ("Completed", "Done"):
            continue

        try:
            raw = provider.get_job_results(job_id)
            counts = raw.get("raw", raw.get("counts", {}))
        except Exception as e:
            print(f"{job_id[:8]}: FETCH ERROR {type(e).__name__}: {e}\n")
            continue

        correlation, total, n_qubits = correct_correlation(counts)
        entry = {
            "job_id": job_id, "created_at": getattr(h, "created_at", None),
            "raw_counts": counts, "total_shots": total,
            "detected_qubit_count": n_qubits,
            "correlation": correlation,
        }
        results.append(entry)

        print(f"{job_id[:8]}  created={entry['created_at']}")
        print(f"  qubits(detected)={n_qubits}  shots={total}  correlation={correlation}")
        print(f"  raw_counts={counts}")
        print()

    print(f"{'='*70}")
    print(f"Total completed jobs with data: {len(results)}")
    print(f"{'='*70}")

    output = {
        "note": ("Fixed version: correlation is computed using the REAL "
                  "detected qubit count per job, not a hardcoded 2-qubit "
                  "assumption. Full raw_counts included for every job so "
                  "any unidentified job can be manually matched to what "
                  "it actually was based on its output pattern."),
        "all_results": results,
        "timestamp": now_iso(),
    }

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "all_jobs_diagnosed_result.json"), "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved full diagnosed dataset.")
