"""Module 132 — Cross-Account Job Metadata Leakage Check

METHOD: module131 tested whether Account B can fetch Account A's job
RESULTS. This tests something narrower and often overlooked: can
Account B see Account A's job STATUS/METADATA (via the scheduler's
get_job call, separate from get_job_results) even for job IDs it
shouldn't know about? Metadata leakage (status, timestamps, backend
used) is a real, subtler risk than full data leakage — it can reveal
usage patterns, timing, and activity without ever exposing measurement
results.

COST: $0 — uses job IDs already submitted earlier tonight, no new
circuit submissions.
"""
import json, datetime, os, signal
import quantum_providers

ACCOUNT_A_ID = os.environ.get("OPENQUANTUM_CLIENT_ID")
ACCOUNT_A_SECRET = os.environ.get("OPENQUANTUM_CLIENT_SECRET")
ACCOUNT_B_ID = "s_d5041ff484784e8eacae281a4fb41564"
ACCOUNT_B_SECRET = "8a30f9502ba82a16b2c6c9035f528569e565c2151e784001d11479fe97a66339"

# Known real job IDs from Account A submitted earlier tonight
KNOWN_ACCOUNT_A_JOB_IDS = [
    "9ceb85e7-f657-43ed-bc35-2e746a7701bd",  # 5-qubit GHZ
    "58c1027d-f80d-474c-9e57-bb8c73d40207",  # fingerprint test
]

class OpTimeout(Exception): pass
def _alarm_handler(s, f): raise OpTimeout()
def with_timeout(func, t, *a, **kw):
    old = signal.signal(signal.SIGALRM, _alarm_handler); signal.alarm(t)
    try: return func(*a, **kw)
    finally: signal.alarm(0); signal.signal(signal.SIGALRM, old)
def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

if __name__ == "__main__":
    print("="*70)
    print("Checking Account A's own view of these jobs (baseline/control)")
    print("="*70)
    os.environ["OPENQUANTUM_CLIENT_ID"] = ACCOUNT_A_ID
    os.environ["OPENQUANTUM_CLIENT_SECRET"] = ACCOUNT_A_SECRET
    provider_a = quantum_providers.get_provider()

    account_a_baseline = {}
    for jid in KNOWN_ACCOUNT_A_JOB_IDS:
        try:
            j = with_timeout(provider_a._scheduler.get_job, 15, jid)
            account_a_baseline[jid] = {"status": j.status}
            print(f"  {jid[:8]} (Account A view): status={j.status}")
        except Exception as e:
            account_a_baseline[jid] = {"error": f"{type(e).__name__}: {e}"}
            print(f"  {jid[:8]} (Account A view): ERROR {e}")

    print(f"\n{'='*70}")
    print("Switching to Account B — attempting to read the SAME job IDs' metadata")
    print(f"{'='*70}")
    os.environ["OPENQUANTUM_CLIENT_ID"] = ACCOUNT_B_ID
    os.environ["OPENQUANTUM_CLIENT_SECRET"] = ACCOUNT_B_SECRET
    provider_b = quantum_providers.get_provider()

    findings = []
    for jid in KNOWN_ACCOUNT_A_JOB_IDS:
        try:
            j = with_timeout(provider_b._scheduler.get_job, 15, jid)
            leaked_status = getattr(j, "status", None)
            print(f"  {jid[:8]} (Account B view): call SUCCEEDED, status={leaked_status}")
            findings.append({"job_id": jid, "account_b_call_succeeded": True,
                               "account_b_saw_status": leaked_status,
                               "matches_account_a": leaked_status == account_a_baseline.get(jid, {}).get("status")})
        except Exception as e:
            print(f"  {jid[:8]} (Account B view): correctly denied — {type(e).__name__}: {e}")
            findings.append({"job_id": jid, "account_b_call_succeeded": False,
                               "error": f"{type(e).__name__}: {e}"})

    any_metadata_leaked = any(f.get("account_b_call_succeeded") and f.get("matches_account_a") for f in findings)

    print(f"\n{'='*70}")
    if any_metadata_leaked:
        verdict = ("FAILED — Account B could read real status metadata for job IDs "
                    "belonging to Account A, matching Account A's own view. This is a "
                    "genuine metadata leak, distinct from (and narrower than) full "
                    "result-data leakage, worth reporting to OpenQuantum.")
    else:
        verdict = ("CONFIRMED — Account B could not retrieve matching real metadata "
                    "for Account A's job IDs, even when guessing/reusing known IDs.")
    print(f"METADATA ISOLATION: {verdict}")
    print(f"{'='*70}")

    result = {"account_a_baseline": account_a_baseline, "account_b_attempts": findings,
               "metadata_leaked": any_metadata_leaked, "verdict": verdict, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module132_metadata_leak_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
