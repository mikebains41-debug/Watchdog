"""Module 133 — Cross-Account Job Cancellation Authorization Test

METHOD: attempts to CANCEL a real, currently-queued job belonging to
Account A, using Account B's credentials. This tests a WRITE/ACTION
authorization boundary, not just a read boundary — a much more
serious category of failure if it succeeds. If Account B can cancel
Account A's real job, that means one customer can disrupt another
customer's work, not just view their data.

HONEST WARNING: if this succeeds, it WILL actually cancel your real
in-flight job. That's an acceptable, informative outcome (confirms a
real finding either way) — but you should know this before running it
rather than be surprised the job disappeared.

COST: $0 in new submissions — uses an already-submitted, already-paid-
for job as the target. Worst case, if isolation fails, you lose that
one job's progress (not a new charge).
"""
import json, datetime, os, signal
import quantum_providers

ACCOUNT_A_ID = os.environ.get("OPENQUANTUM_CLIENT_ID")
ACCOUNT_A_SECRET = os.environ.get("OPENQUANTUM_CLIENT_SECRET")
ACCOUNT_B_ID = "s_d5041ff484784e8eacae281a4fb41564"
ACCOUNT_B_SECRET = "8a30f9502ba82a16b2c6c9035f528569e565c2151e784001d11479fe97a66339"

# Pick the currently-queued 5-qubit GHZ job as the target — real,
# in-flight, known to still be Queued as of the last check tonight
TARGET_JOB_ID = "9ceb85e7-f657-43ed-bc35-2e746a7701bd"

class OpTimeout(Exception): pass
def _alarm_handler(s, f): raise OpTimeout()
def with_timeout(func, t, *a, **kw):
    old = signal.signal(signal.SIGALRM, _alarm_handler); signal.alarm(t)
    try: return func(*a, **kw)
    finally: signal.alarm(0); signal.signal(signal.SIGALRM, old)
def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

if __name__ == "__main__":
    print(f"Target job (Account A, should still be Queued): {TARGET_JOB_ID}\n")

    print("="*70)
    print("Confirming target job's current status via Account A (control)")
    print("="*70)
    os.environ["OPENQUANTUM_CLIENT_ID"] = ACCOUNT_A_ID
    os.environ["OPENQUANTUM_CLIENT_SECRET"] = ACCOUNT_A_SECRET
    provider_a = quantum_providers.get_provider()

    status_before = None
    try:
        j = with_timeout(provider_a._scheduler.get_job, 15, TARGET_JOB_ID)
        status_before = j.status
        print(f"  Status before attempt: {status_before}")
    except Exception as e:
        print(f"  Could not check status: {type(e).__name__}: {e}")

    if status_before not in ("Pending", "Queued", "Running"):
        print(f"\nTarget job is not in a cancelable state ({status_before}) — "
              f"aborting this test rather than getting a meaningless result.")
        result = {"target_job_id": TARGET_JOB_ID, "status_before": status_before,
                    "note": "Job not in cancelable state, test not run.", "timestamp": now_iso()}
    else:
        print(f"\n{'='*70}")
        print("Switching to Account B, attempting to CANCEL Account A's job")
        print(f"{'='*70}")
        os.environ["OPENQUANTUM_CLIENT_ID"] = ACCOUNT_B_ID
        os.environ["OPENQUANTUM_CLIENT_SECRET"] = ACCOUNT_B_SECRET
        provider_b = quantum_providers.get_provider()

        cancel_succeeded = False
        cancel_error = None
        for method_name in ("cancel_job", "delete_job"):
            if hasattr(provider_b._scheduler, method_name):
                try:
                    with_timeout(getattr(provider_b._scheduler, method_name), 15, TARGET_JOB_ID)
                    cancel_succeeded = True
                    print(f"  Cancel call via {method_name} did not raise an error")
                    break
                except Exception as e:
                    cancel_error = f"{type(e).__name__}: {e}"
                    print(f"  {method_name} correctly denied: {cancel_error}")

        print(f"\n{'='*70}")
        print("Verifying actual real-world effect via Account A")
        print(f"{'='*70}")
        os.environ["OPENQUANTUM_CLIENT_ID"] = ACCOUNT_A_ID
        os.environ["OPENQUANTUM_CLIENT_SECRET"] = ACCOUNT_A_SECRET
        provider_a2 = quantum_providers.get_provider()
        status_after = None
        try:
            j2 = with_timeout(provider_a2._scheduler.get_job, 15, TARGET_JOB_ID)
            status_after = j2.status
            print(f"  Status after Account B's attempt: {status_after}")
        except Exception as e:
            print(f"  Could not verify: {type(e).__name__}: {e}")

        actually_canceled = (status_after == "Canceled" and status_before != "Canceled")

        print(f"\n{'='*70}")
        if actually_canceled:
            verdict = ("FAILED — Account B's cancel call actually changed Account A's real "
                        "job to Canceled. This is a genuine, serious cross-tenant write "
                        "authorization failure, worth reporting to OpenQuantum immediately.")
        elif cancel_succeeded and not actually_canceled:
            verdict = ("INCONCLUSIVE — the API call returned without error, but the job's "
                        "real status did not actually change. Likely means the call was a "
                        "silent no-op for the wrong tenant rather than a real cancellation — "
                        "still worth flagging that it doesn't return a clear permission error.")
        else:
            verdict = "CONFIRMED — Account B could not cancel Account A's real job."
        print(f"CANCELLATION AUTHORIZATION: {verdict}")
        print(f"{'='*70}")

        result = {
            "target_job_id": TARGET_JOB_ID, "status_before": status_before,
            "cancel_call_succeeded_without_error": cancel_succeeded,
            "cancel_error": cancel_error, "status_after": status_after,
            "actually_canceled_by_wrong_account": actually_canceled,
            "verdict": verdict, "timestamp": now_iso(),
        }

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module133_cancel_auth_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
