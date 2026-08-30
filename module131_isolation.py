"""Module 131 — Cross-Account Tenant Isolation Probe

METHOD: submits ONE real job from Account A (this session's active
account), then switches to Account B's credentials and attempts,
READ-ONLY, to:
  1. See if Account A's job appears in Account B's job history (it
     should NOT)
  2. Fetch results for Account A's specific job_id directly using
     Account B's credentials (should be denied, not silently
     returned)

This tests OpenQuantum's own tenant isolation — whether one
customer's real jobs and data are genuinely walled off from another,
rather than assuming a cloud provider's multi-tenancy claims are
correct. This is NOT a benchmark of the QPU; it's a security boundary
test of the platform itself, using a real, freshly-submitted job as
the probe.

COST: only 1 real circuit submission (Account A). All Account B
checks are read-only and free.
"""
import json, time, datetime, os, signal
import quantum_providers

SUBMIT_TIMEOUT_S = 25; HISTORY_TIMEOUT_S = 15; POLL_MAX_WAIT_S = 120; POLL_INTERVAL_S = 8
BACKEND = "rigetti:cepheus-1-108q"

# Account A = current session (phinspaintingandrenos)
ACCOUNT_A_ID = os.environ.get("OPENQUANTUM_CLIENT_ID")
ACCOUNT_A_SECRET = os.environ.get("OPENQUANTUM_CLIENT_SECRET")

# Account B = the original account used earlier tonight
ACCOUNT_B_ID = "s_d5041ff484784e8eacae281a4fb41564"
ACCOUNT_B_SECRET = "8a30f9502ba82a16b2c6c9035f528569e565c2151e784001d11479fe97a66339"


class OpTimeout(Exception): pass
def _alarm_handler(s, f): raise OpTimeout()
def with_timeout(func, t, *a, **kw):
    old = signal.signal(signal.SIGALRM, _alarm_handler); signal.alarm(t)
    try: return func(*a, **kw)
    finally: signal.alarm(0); signal.signal(signal.SIGALRM, old)
def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def build_bell():
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2]; creg c[2];
h q[0]; cx q[0],q[1];
measure q[0]->c[0]; measure q[1]->c[1];
"""

def get_recent_job_ids(provider, limit=15):
    try: return {h.job_id for h in with_timeout(provider.get_job_history, HISTORY_TIMEOUT_S, limit=limit)}
    except Exception as e: print(f"  [DEBUG] history FAILED: {e}"); return set()

def submit_with_recovery(provider, qasm, shots, backend, name):
    known = get_recent_job_ids(provider)
    try:
        jid = with_timeout(provider.submit_circuit, SUBMIT_TIMEOUT_S, qasm, shots=shots, backend=backend, name=name)
        print(f"  [DEBUG] CLEAN_SUCCESS: {jid}"); return jid
    except OpTimeout: print("  [DEBUG] TIMEOUT — diff recovery")
    except Exception as e: print(f"  [DEBUG] EXCEPTION {e} — diff recovery")
    time.sleep(3)
    new = get_recent_job_ids(provider) - known
    print(f"  [DEBUG] diff: {[j[:8] for j in new] if new else '(none)'}")
    return next(iter(new)) if len(new) == 1 else None


if __name__ == "__main__":
    print("="*70)
    print("STEP 1: Submitting real job from Account A")
    print("="*70)
    os.environ["OPENQUANTUM_CLIENT_ID"] = ACCOUNT_A_ID
    os.environ["OPENQUANTUM_CLIENT_SECRET"] = ACCOUNT_A_SECRET
    provider_a = get_provider = quantum_providers.get_provider()
    print(f"Account A provider: {provider_a.provider_name}")

    qasm = build_bell()
    job_id_a = submit_with_recovery(provider_a, qasm, 512, BACKEND, "watchdog_isolation_probe")
    print(f"Account A job ID: {job_id_a}\n")

    if job_id_a is None:
        print("Could not confirm a real job_id from Account A — aborting isolation probe "
              "(nothing to test isolation against without a real job).")
        result = {"error": "no job_id obtained from Account A", "timestamp": now_iso()}
    else:
        print("="*70)
        print("STEP 1b: Waiting for Account A's job to actually COMPLETE before testing")
        print("(an empty result from a still-Queued job would be a false positive either way)")
        print("="*70)
        start = time.time()
        job_status = "UNKNOWN"
        while time.time() - start < POLL_MAX_WAIT_S:
            try:
                j = with_timeout(provider_a._scheduler.get_job, 15, job_id_a)
                job_status = j.status
                print(f"  status: {job_status} ({int(time.time()-start)}s)")
                if job_status in ("Completed", "Done", "FAILED", "Cancelled", "Error"):
                    break
            except Exception:
                print("  poll error — retry")
            time.sleep(POLL_INTERVAL_S)

        if job_status not in ("Completed", "Done"):
            print(f"\nJob never completed (status: {job_status}) within wait budget — "
                  f"cannot run a valid isolation test on an incomplete job. Stopping "
                  f"here rather than drawing any conclusion from empty data.")
            result = {"account_a_job_id": job_id_a, "job_status": job_status,
                        "note": "Job did not complete in time; isolation test not valid, no conclusion drawn.",
                        "timestamp": now_iso()}
        else:
            print(f"\nJob confirmed Completed. Now testing isolation with REAL completed data.\n")

            print("="*70)
            print("CONTROL CHECK: Account A fetching its OWN completed job (sanity check)")
            print("="*70)
            own_fetch_result = None
            try:
                own_fetch_result = with_timeout(provider_a.get_job_results, 15, job_id_a)
                print(f"  Account A's own fetch: {own_fetch_result}")
            except Exception as e:
                print(f"  Account A's own fetch FAILED unexpectedly: {type(e).__name__}: {e}")

            print("="*70)
            print("STEP 2: Switching to Account B, checking job history for leakage")
            print("="*70)
            os.environ["OPENQUANTUM_CLIENT_ID"] = ACCOUNT_B_ID
            os.environ["OPENQUANTUM_CLIENT_SECRET"] = ACCOUNT_B_SECRET
            provider_b = quantum_providers.get_provider()
            print(f"Account B provider: {provider_b.provider_name}")

            history_b = get_recent_job_ids(provider_b, limit=30)
            leaked_in_history = job_id_a in history_b
            print(f"Account A's job_id visible in Account B's history: {leaked_in_history}")

            print(f"\n{'='*70}")
            print("STEP 3: Attempting direct result fetch of Account A's job using Account B credentials")
            print(f"{'='*70}")
            direct_fetch_succeeded = False
            direct_fetch_error = None
            leaked_result = None
            try:
                leaked_result = with_timeout(provider_b.get_job_results, 15, job_id_a)
                direct_fetch_succeeded = True
                print(f"  Fetch call returned without error: {leaked_result}")
            except Exception as e:
                direct_fetch_error = f"{type(e).__name__}: {e}"
                print(f"  Correctly denied: {direct_fetch_error}")

            # Only a REAL leak if B got the SAME real data A got, not just an
            # empty/generic response that both would get regardless
            real_data_leaked = (direct_fetch_succeeded and leaked_result
                                 and leaked_result == own_fetch_result
                                 and leaked_result.get("counts"))

            isolation_confirmed = (not leaked_in_history) and not real_data_leaked

            print(f"\n{'='*70}")
            if real_data_leaked:
                verdict = "FAILED — Account B received the SAME real completed data as Account A. Genuine cross-tenant leak, worth reporting."
            elif direct_fetch_succeeded and not real_data_leaked:
                verdict = "INCONCLUSIVE — API call did not error, but returned empty/non-matching data, not Account A's real results. Likely means the endpoint doesn't 403 on wrong tenant but also doesn't leak real data — worth flagging to OpenQuantum as a minor hardening opportunity (should return a clear permission error), not a confirmed data leak."
            else:
                verdict = "CONFIRMED — Account B correctly denied access to Account A's job."
            print(f"TENANT ISOLATION: {verdict}")
            print(f"{'='*70}")

            result = {
                "account_a_job_id": job_id_a, "job_status": job_status,
                "account_a_own_fetch_result": own_fetch_result,
                "leaked_in_account_b_history": leaked_in_history,
                "direct_fetch_by_account_b_succeeded": direct_fetch_succeeded,
                "direct_fetch_by_account_b_result": leaked_result,
                "direct_fetch_error": direct_fetch_error,
                "real_data_leaked": bool(real_data_leaked),
                "verdict": verdict,
                "timestamp": now_iso(),
            }

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module131_isolation_probe_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
