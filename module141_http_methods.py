"""Module 141 — HTTP Method Tampering Test
Attack tested: sending unexpected HTTP verbs (PUT, DELETE, PATCH,
TRACE) against real known API endpoints, hoping to hit an
unintended/undocumented handler — a real, common way attackers
discover hidden admin functionality or bypass access controls that
were only enforced for the "normal" verb (e.g. GET/POST).

METHOD: sends real HTTP requests with non-standard methods to the
real OpenQuantum token endpoint and checks whether any unexpected verb
is silently accepted rather than cleanly rejected (405 Method Not
Allowed is the correct, safe response).

COST: $0 — raw HTTP requests, no valid credentials sent, no credits.
"""
import requests, json, datetime, os

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

TOKEN_URL = "https://id.openquantum.com/realms/platform/protocol/openid-connect/token"
METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "OPTIONS", "HEAD"]

if __name__ == "__main__":
    print(f"--- HTTP Method Tampering Test on {TOKEN_URL} ---\n")
    findings = []
    for method in METHODS:
        print(f"Trying {method}...")
        try:
            resp = requests.request(method, TOKEN_URL, timeout=12)
            status = resp.status_code
            unexpected_success = status not in (405, 404, 400, 401)
            print(f"  Status: {status}"
                  + ("  *** UNEXPECTED — worth investigating ***" if unexpected_success else " (expected rejection)"))
            findings.append({"method": method, "status_code": status,
                               "unexpected_success": unexpected_success})
        except Exception as e:
            print(f"  Request failed: {type(e).__name__}: {e}")
            findings.append({"method": method, "error": str(e)})

    unexpected = [f for f in findings if f.get("unexpected_success")]

    print(f"\n{'='*60}")
    print(f"Methods with unexpected (non-error) responses: {len(unexpected)}/{len(METHODS)}")
    print(f"{'='*60}")

    finding_summary = (
        f"Tested {len(METHODS)} non-standard HTTP methods against the real "
        f"OpenQuantum token endpoint. "
        + (f"{len(unexpected)} returned an unexpected non-error status — worth "
           f"investigating what handler responded." if unexpected else
           "All were correctly rejected with standard error codes (405/404/400/401) "
           "— no hidden method-based endpoint behavior found.")
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"endpoint": TOKEN_URL, "findings": findings,
               "unexpected_count": len(unexpected),
               "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module141_http_methods_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
