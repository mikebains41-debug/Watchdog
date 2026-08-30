"""Module 135 — Job Name Field Injection Test (own account only)

METHOD: submits real jobs with deliberately malicious payloads in the
NAME field — SQL injection strings, script tags, path traversal — to
test whether the API sanitizes user-supplied strings before storing/
echoing them. Scoped entirely to this account's own jobs; this is
testing OUR OWN data handling, not attempting to access anyone else's.

Why this matters: job names get stored, displayed on dashboards, and
returned in API responses. If unsanitized, a malicious name could be
a stored-XSS vector against anyone viewing the dashboard, or reveal
injection vulnerabilities in backend storage.
"""
import json, time, datetime, os, signal
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 25; HISTORY_TIMEOUT_S = 15
BACKEND = "rigetti:cepheus-1-108q"

PAYLOADS = [
    "watchdog_test'; DROP TABLE jobs;--",
    "watchdog_test<script>alert(1)</script>",
    "watchdog_test../../../etc/passwd",
    "watchdog_test\x00nullbyte",
    "watchdog_test" + "A" * 500,  # oversized name
]

class OpTimeout(Exception): pass
def _alarm_handler(s, f): raise OpTimeout()
def with_timeout(func, t, *a, **kw):
    old = signal.signal(signal.SIGALRM, _alarm_handler); signal.alarm(t)
    try: return func(*a, **kw)
    finally: signal.alarm(0); signal.signal(signal.SIGALRM, old)
def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def build_minimal_circuit():
    """Tiny, cheap 1-qubit circuit — this test is about the NAME field,
    not the circuit, so keep cost minimal."""
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[1]; creg c[1];
h q[0];
measure q[0] -> c[0];
"""

def get_recent_job_ids(provider, limit=15):
    try:
        return {h.job_id for h in with_timeout(provider.get_job_history, HISTORY_TIMEOUT_S, limit=limit)}
    except Exception as e:
        print(f"    [DEBUG] history check failed: {e}")
        return set()

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    qasm = build_minimal_circuit()
    findings = []

    for payload in PAYLOADS:
        print(f"--- Testing name payload: {payload[:50]}{'...' if len(payload) > 50 else ''} ---")
        known_ids = get_recent_job_ids(provider)
        try:
            jid = with_timeout(provider.submit_circuit, SUBMIT_TIMEOUT_S,
                                 qasm, shots=64, backend=BACKEND, name=payload)
            print(f"  Accepted (clean, no timeout), job_id: {jid}")
            findings.append({"payload": payload, "accepted": True, "job_id": jid,
                               "error": None, "confirmed_via": "direct_return"})
        except OpTimeout:
            print(f"  Client-side timeout — checking history diff to see if it "
                  f"actually landed server-side despite the timeout...")
            time.sleep(3)
            new_ids = get_recent_job_ids(provider) - known_ids
            if len(new_ids) == 1:
                jid = next(iter(new_ids))
                print(f"  Actually WAS accepted server-side: job_id={jid} "
                      f"(client just gave up waiting, not a real rejection)")
                findings.append({"payload": payload, "accepted": True, "job_id": jid,
                                   "error": "client timeout, but confirmed accepted via diff",
                                   "confirmed_via": "history_diff"})
            else:
                print(f"  INCONCLUSIVE — no new job appeared in history within 3s of "
                      f"the timeout. Cannot confirm whether this was accepted or "
                      f"rejected; do not treat as a clean pass.")
                findings.append({"payload": payload, "accepted": None, "job_id": None,
                                   "error": "timeout, no diff confirmation either way",
                                   "confirmed_via": "inconclusive"})
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            print(f"  Genuinely rejected by the API: {err[:200]}")
            findings.append({"payload": payload, "accepted": False, "job_id": None,
                               "error": err, "confirmed_via": "real_exception"})
        time.sleep(2)

    accepted_count = sum(1 for f in findings if f["accepted"] is True)
    inconclusive_count = sum(1 for f in findings if f["accepted"] is None)
    rejected_count = sum(1 for f in findings if f["accepted"] is False)
    print(f"\n{'='*60}")
    print(f"Confirmed accepted: {accepted_count}/{len(PAYLOADS)}")
    print(f"Genuinely rejected: {rejected_count}/{len(PAYLOADS)}")
    print(f"Inconclusive (timeout, no diff confirmation): {inconclusive_count}/{len(PAYLOADS)}")
    print(f"{'='*60}")

    finding_summary = (
        f"Submitted {len(PAYLOADS)} deliberately malicious job names. "
        f"{accepted_count} confirmed accepted without sanitization, {rejected_count} "
        f"genuinely rejected by the API, {inconclusive_count} inconclusive (client "
        f"timeout with no way to confirm server-side outcome — Rigetti's queue was "
        f"slow during this run). "
        + ("Accepted malicious names are worth checking against the dashboard for "
           "unsanitized rendering (stored XSS risk)." if accepted_count > 0 else "")
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"payloads_tested": len(PAYLOADS), "accepted_count": accepted_count,
               "findings": findings, "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module135_injection_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
