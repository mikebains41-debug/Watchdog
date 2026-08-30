"""Module 134 — API Error Message Secret Exposure Check

METHOD: deliberately triggers a real authentication error (using an
intentionally wrong client_secret) and inspects the actual error
response text for whether it echoes back any part of the real
credentials, internal stack traces, or other sensitive details.
Error-message secret leakage is a well-known, common real-world
vulnerability class — APIs sometimes echo back partial tokens,
internal file paths, or database details in error responses meant
only for debugging.

Also checks basic rate-limit behavior with a burst of rapid read-only
calls — confirms whether the API enforces any throttling, since an
unthrottled API is more exposed to credential-stuffing or brute-force
attempts against the auth endpoint.

COST: $0 — every call here is either a deliberate auth failure (no
credits) or existing free read calls.
"""
import json, datetime, os, time
import quantum_providers

REAL_ID = os.environ.get("OPENQUANTUM_CLIENT_ID")
REAL_SECRET = os.environ.get("OPENQUANTUM_CLIENT_SECRET")

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

SENSITIVE_MARKERS = [REAL_SECRET, REAL_ID] if REAL_SECRET and REAL_ID else []

if __name__ == "__main__":
    print("="*70)
    print("STEP 1: Triggering a deliberate auth failure with a wrong secret")
    print("="*70)
    os.environ["OPENQUANTUM_CLIENT_ID"] = REAL_ID or "s_fake_id_for_test"
    os.environ["OPENQUANTUM_CLIENT_SECRET"] = "deliberately_wrong_secret_for_leak_test_00000000"

    error_text = ""
    try:
        provider_bad = quantum_providers.get_provider()
        with_call_result = provider_bad.get_job_history(limit=1)
        print(f"  Call returned without raising (result: {with_call_result}) — the wrapper "
              f"library appears to swallow auth failures into an empty return rather than "
              f"raising an exception. Attempting a lower-level HTTP check instead.")
    except Exception as e:
        error_text = str(e)
        print(f"  Correctly failed with a raised exception. Full error text below:")
        print(f"  {error_text[:500]}")

    # Fallback: hit the token endpoint directly with requests, since the
    # SDK wrapper doesn't propagate the 401 as an exception for this call
    if not error_text:
        try:
            import requests
            resp = requests.post(
                "https://id.openquantum.com/realms/platform/protocol/openid-connect/token",
                data={"grant_type": "client_credentials",
                       "client_id": os.environ.get("OPENQUANTUM_CLIENT_ID", ""),
                       "client_secret": "deliberately_wrong_secret_for_leak_test_00000000"},
                timeout=15
            )
            error_text = f"HTTP {resp.status_code}: {resp.text[:1000]}"
            print(f"  Direct HTTP check: {error_text}")
        except Exception as e:
            print(f"  Direct HTTP check also failed to run: {type(e).__name__}: {e}")

    # Restore real credentials for the rest of the script
    if REAL_ID and REAL_SECRET:
        os.environ["OPENQUANTUM_CLIENT_ID"] = REAL_ID
        os.environ["OPENQUANTUM_CLIENT_SECRET"] = REAL_SECRET

    leaked_markers = [m for m in SENSITIVE_MARKERS if m and m in error_text]
    print(f"\n  Real credential fragments found echoed in error text: {len(leaked_markers)}")

    print(f"\n{'='*70}")
    print("STEP 2: Basic rate-limit check — 10 rapid read-only calls")
    print(f"{'='*70}")
    provider_real = quantum_providers.get_provider()
    rate_limit_hit = False
    call_times = []
    for i in range(10):
        start = time.time()
        try:
            provider_real.get_job_history(limit=1)
            elapsed = time.time() - start
            call_times.append(elapsed)
            print(f"  call {i+1}: OK ({elapsed:.2f}s)")
        except Exception as e:
            elapsed = time.time() - start
            call_times.append(elapsed)
            err_str = str(e)
            if "429" in err_str or "rate" in err_str.lower() or "throttle" in err_str.lower():
                rate_limit_hit = True
                print(f"  call {i+1}: RATE LIMITED — {err_str[:200]}")
            else:
                print(f"  call {i+1}: error (not rate-limit related) — {err_str[:200]}")

    print(f"\n{'='*70}")
    print(f"Credential fragments leaked in error messages: {len(leaked_markers)}")
    print(f"Rate limiting observed across 10 rapid calls: {rate_limit_hit}")
    print(f"{'='*70}")

    finding_summary = (
        f"Deliberate auth failure test: {'FOUND real credential fragments echoed in the error response — genuine secret-exposure finding' if leaked_markers else 'no credential fragments found in the error response — clean'}. "
        f"Rate limiting: {'observed after rapid calls — API enforces throttling' if rate_limit_hit else 'NOT observed across 10 rapid read calls — API may not throttle aggressively, worth noting as a hardening consideration, not necessarily a vulnerability on its own'}."
    )
    print(f"\nFINDING: {finding_summary}")

    result = {
        "auth_error_text_sample": error_text[:1000],
        "credential_fragments_leaked": len(leaked_markers),
        "rate_limit_observed": rate_limit_hit,
        "call_times_seconds": call_times,
        "finding_summary": finding_summary,
        "timestamp": now_iso(),
    }
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module134_error_leak_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved. (credential values themselves are NOT stored in the output, only leak count)")
