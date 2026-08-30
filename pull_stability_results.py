"""
pull_stability_results.py — the original module113 only waited 120s
per run before giving up and moving to the next submission. The
dashboard now shows most of those runs actually completed 1-2 HOURS
later (real queue delay on Rigetti tonight — itself a genuine finding
about real-world queue behavior, not a bug). This script goes back
and pulls the real, final results for every job in the stability run
series, rebuilding the complete time-series dataset.
"""
import json
import datetime
import os
from quantum_providers import get_provider

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def correlation_fraction(counts, total):
    if not total:
        return None
    return (counts.get("00", 0) + counts.get("11", 0)) / total

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    history = provider.get_job_history(limit=20)
    print(f"Fetched {len(history)} recent jobs from history\n")

    results = []
    for h in history:
        status = h.status
        job_id = h.job_id
        print(f"Checking {job_id[:8]}... status={status}")

        entry = {"job_id": job_id, "status": status, "created_at": getattr(h, "created_at", None)}

        if status in ("Completed", "Done"):
            try:
                raw = provider.get_job_results(job_id)
                counts = raw.get("raw", raw.get("counts", {}))
                total = sum(counts.values()) if counts else 0
                fidelity = correlation_fraction(counts, total)
                entry.update({"counts": counts, "shots": total, "fidelity": fidelity})
                print(f"  fidelity: {fidelity}")
            except Exception as e:
                entry["fetch_error"] = f"{type(e).__name__}: {e}"
                print(f"  could not fetch results: {e}")

        results.append(entry)

    completed_with_fidelity = [r for r in results if r.get("fidelity") is not None]
    print(f"\n{'='*60}")
    print(f"Total jobs checked: {len(results)}")
    print(f"Completed with real fidelity data: {len(completed_with_fidelity)}")
    print(f"{'='*60}\n")

    for r in sorted(completed_with_fidelity, key=lambda x: x.get("created_at") or ""):
        print(f"  {r['job_id'][:8]}  created={r.get('created_at')}  fidelity={r['fidelity']:.4f}")

    if completed_with_fidelity:
        fidelities = [r["fidelity"] for r in completed_with_fidelity]
        print(f"\nFidelity range: {min(fidelities):.4f} - {max(fidelities):.4f}")
        print(f"Average: {sum(fidelities)/len(fidelities):.4f}")
        print(f"Std spread (max-min): {max(fidelities)-min(fidelities):.4f}")

    output = {
        "backend": "rigetti:cepheus-1-108q",
        "note": ("Rebuilt from real job history after original module113 poll "
                  "windows (120s each) gave up before jobs actually completed. "
                  "Real completion times were 1-2 hours after submission -- "
                  "genuine evidence of Rigetti's real-world queue behavior "
                  "during this session, separate from the fidelity data itself."),
        "all_jobs_checked": results,
        "completed_with_fidelity": completed_with_fidelity,
        "timestamp": now_iso(),
    }

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module113_stability_FULL_result.json"), "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved full rebuilt dataset.")
