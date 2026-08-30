"""Module 138 — Result Consistency & Shot-Count Integrity Check
Attacks tested: result substitution between completion and fetch,
silent shot-count downgrading (billing/execution mismatch).

METHOD: for each already-completed job, fetches results TWICE and
checks they're byte-identical (a real fetch should return the same
stored result every time — if it changes, someone's tampering with
data at rest). Also verifies the total measured shots match exactly
what was requested at submission (a downgrade attack would silently
execute fewer shots than paid for).

COST: $0 — read-only, reuses already-completed jobs.
"""
import json, datetime, os
from quantum_providers import get_provider

EXPECTED_SHOTS = {
    "9d148293": 1024, "33369a45": 1024, "bf428e6b": 1024,
    "511ee10c": 1024, "f85374d7": 1024,
}

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    history = provider.get_job_history(limit=25)
    completed = [h for h in history if h.status in ("Completed", "Done")]
    print(f"Found {len(completed)} completed jobs to check\n")

    findings = []
    for h in completed:
        jid = h.job_id
        short = jid[:8]
        print(f"--- {short} ---")
        try:
            r1 = provider.get_job_results(jid)
            r2 = provider.get_job_results(jid)
            identical = (r1 == r2)
            counts = r1.get("raw", {})
            total_shots = sum(counts.values())
            expected = EXPECTED_SHOTS.get(short)
            shots_match = (total_shots == expected) if expected else None

            print(f"  Two fetches identical: {identical}")
            print(f"  Total measured shots: {total_shots}"
                  + (f" (expected {expected}, match={shots_match})" if expected else " (expected count unknown)"))

            findings.append({"job_id": jid, "fetches_identical": identical,
                               "total_shots": total_shots, "expected_shots": expected,
                               "shots_match": shots_match})
        except Exception as e:
            print(f"  Could not check: {type(e).__name__}: {e}")
            findings.append({"job_id": jid, "error": str(e)})

    inconsistent = [f for f in findings if f.get("fetches_identical") is False]
    shot_mismatches = [f for f in findings if f.get("shots_match") is False]

    print(f"\n{'='*60}")
    print(f"Jobs with INCONSISTENT repeated fetches: {len(inconsistent)}")
    print(f"Jobs with shot-count MISMATCH from expected: {len(shot_mismatches)}")
    print(f"{'='*60}")

    finding_summary = (
        f"Checked {len(completed)} completed jobs for result consistency and "
        f"shot-count integrity. {len(inconsistent)} showed different data between "
        f"two consecutive fetches of the SAME job (would indicate result tampering "
        f"or mutation at rest). {len(shot_mismatches)} showed a mismatch between "
        f"requested and actually-measured shot count (would indicate silent "
        f"execution/billing downgrade). "
        + ("Both are real findings worth investigating." if (inconsistent or shot_mismatches)
           else "No inconsistencies found — results are stable across fetches and shot counts match requests where known.")
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"jobs_checked": len(completed), "findings": findings,
               "inconsistent_count": len(inconsistent), "shot_mismatch_count": len(shot_mismatches),
               "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module138_result_integrity_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
