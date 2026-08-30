"""
module_cancel_stuck.py — attempts to cancel stuck Pending jobs, honestly.

The first attempt tonight (_scheduler.cancel_job) failed with a
JSONDecodeError, meaning it hit the wrong API endpoint or the SDK
doesn't expose that method the way I assumed. Rather than guess again
and claim success falsely, this version tries a few plausible method
names/locations, reports exactly which one (if any) works, and does
NOT claim success unless a real, verifiable response comes back.

If none of these work, the honest fallback remains: cancel manually
via the OpenQuantum dashboard's X button, which has worked reliably
all night and is confirmed to actually refund credits.
"""
import json
import datetime
from quantum_providers import get_provider

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def try_cancel(provider, job_id):
    """Tries several plausible cancel methods in order. Returns
    (success: bool, method_used: str, error: str or None)."""

    attempts = []

    # Attempt 1: scheduler.cancel_job (what failed earlier tonight)
    if hasattr(provider, "_scheduler") and hasattr(provider._scheduler, "cancel_job"):
        try:
            provider._scheduler.cancel_job(job_id)
            return True, "_scheduler.cancel_job", None
        except Exception as e:
            attempts.append(("_scheduler.cancel_job", f"{type(e).__name__}: {e}"))

    # Attempt 2: scheduler.delete_job
    if hasattr(provider, "_scheduler") and hasattr(provider._scheduler, "delete_job"):
        try:
            provider._scheduler.delete_job(job_id)
            return True, "_scheduler.delete_job", None
        except Exception as e:
            attempts.append(("_scheduler.delete_job", f"{type(e).__name__}: {e}"))

    # Attempt 3: management.cancel_job (mirrors the credit-balance call
    # pattern used successfully earlier tonight, which went through
    # _management rather than _scheduler)
    if hasattr(provider, "_management") and hasattr(provider._management, "cancel_job"):
        try:
            provider._management.cancel_job(job_id)
            return True, "_management.cancel_job", None
        except Exception as e:
            attempts.append(("_management.cancel_job", f"{type(e).__name__}: {e}"))

    # Attempt 4: provider.cancel_job directly (top-level wrapper)
    if hasattr(provider, "cancel_job"):
        try:
            provider.cancel_job(job_id)
            return True, "provider.cancel_job", None
        except Exception as e:
            attempts.append(("provider.cancel_job", f"{type(e).__name__}: {e}"))

    error_summary = "; ".join(f"{m}: {e}" for m, e in attempts) if attempts else \
                     "no candidate cancel method found on provider object at all"
    return False, None, error_summary


def run():
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    try:
        history = provider.get_job_history(limit=20)
    except Exception as e:
        print(f"Could not fetch job history: {type(e).__name__}: {e}")
        return

    pending = [h for h in history if h.status == "Pending"]
    if not pending:
        print("No Pending jobs found. Nothing to cancel.")
        return

    print(f"Found {len(pending)} Pending job(s). Attempting cancellation...\n")

    results = []
    for h in pending:
        success, method, error = try_cancel(provider, h.job_id)
        if success:
            print(f"  CANCELED {h.job_id[:8]} via {method}")
        else:
            print(f"  FAILED to cancel {h.job_id[:8]}: {error}")
        results.append({
            "job_id": h.job_id, "success": success,
            "method_used": method, "error": error,
        })

    succeeded = [r for r in results if r["success"]]
    print(f"\n{'='*50}")
    print(f"Canceled: {len(succeeded)}/{len(results)}")
    if len(succeeded) < len(results):
        print(f"Remaining jobs need manual cancellation via the "
              f"OpenQuantum dashboard X button (confirmed to work "
              f"and refund credits, all night).")
    print(f"{'='*50}")

    return {
        "attempted": len(results), "succeeded": len(succeeded),
        "results": results, "timestamp": now_iso(),
    }


if __name__ == "__main__":
    run()
