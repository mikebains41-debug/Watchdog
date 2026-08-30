"""
check_status.py — standalone OpenQuantum job status checker

Run this any time to see where all recent Watchdog jobs stand, without
retyping the inline python3 -c command each time and without
resubmitting anything. Read-only — this never submits a job or spends
credits, it only queries existing job status.

Usage (from Watchdog/, with credentials already exported):
    python3 check_status.py
"""
import os
from quantum_providers import get_provider

HISTORY_LIMIT = 15  # how many recent jobs to pull

DONE_STATES = ("Completed", "Done")
DEAD_STATES = ("Canceled", "Cancelled", "FAILED", "Error")


def main():
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    try:
        history = provider.get_job_history(limit=HISTORY_LIMIT)
    except Exception as e:
        print(f"Could not fetch job history: {type(e).__name__}: {e}")
        return

    if not history:
        print("No jobs found.")
        return

    pending = []
    done = []
    dead = []

    print(f"{'JOB ID':<10} {'NAME':<32} {'STATUS':<12} {'CREATED'}")
    print("-" * 80)
    for h in history:
        job_id = h.job_id[:8]
        name = getattr(h, "name", None) or "(no name)"
        status = h.status
        created = getattr(h, "created_at", "?")
        print(f"{job_id:<10} {name[:32]:<32} {status:<12} {created}")

        if status in DONE_STATES:
            done.append(h)
        elif status in DEAD_STATES:
            dead.append(h)
        else:
            pending.append(h)

    print("\n" + "=" * 80)
    print(f"SUMMARY: {len(pending)} still pending/running, "
          f"{len(done)} completed, {len(dead)} canceled/failed")
    print("=" * 80)

    if pending:
        print("\nStill waiting on:")
        for h in pending:
            name = getattr(h, "name", None) or "(no name)"
            print(f"  {h.job_id[:8]}  {name}  ({h.status})")
        print("\nNo action needed — just re-run this script later to check again.")
        print("Do NOT resubmit these tests while they're still pending; that")
        print("only creates duplicate jobs and spends more credits.")

    if done:
        print("\nReady to pull results for:")
        for h in done:
            name = getattr(h, "name", None) or "(no name)"
            print(f"  {h.job_id[:8]}  {name}")
        print("\nPull results with: provider.get_job_results('<full_job_id>')")
        print("(use the full job_id, not the shortened 8-char version above —")
        print(" full IDs are visible in the OpenQuantum dashboard job cards)")


if __name__ == "__main__":
    main()
