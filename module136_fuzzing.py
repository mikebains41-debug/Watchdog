"""Module 136 — Malformed Input Fuzzing (own account only)

METHOD: submits deliberately broken/extreme inputs — garbage QASM,
negative shots, zero shots, absurd shot counts, nonexistent backend
names — to see whether the API fails gracefully with clean validation
errors, or leaks stack traces / internal details / crashes unexpectedly.

Most of these should be REJECTED before any real hardware time is
used, so this test should cost close to $0 in credits — invalid
submissions typically fail validation before scheduling.
"""
import json, time, datetime, os, signal
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 20
BACKEND = "rigetti:cepheus-1-108q"

VALID_QASM = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[1]; creg c[1];
h q[0];
measure q[0] -> c[0];
"""

TEST_CASES = [
    {"desc": "garbage QASM (not valid syntax)", "qasm": "THIS IS NOT VALID QASM AT ALL {{{",
      "shots": 64, "backend": BACKEND},
    {"desc": "negative shots", "qasm": VALID_QASM, "shots": -100, "backend": BACKEND},
    {"desc": "zero shots", "qasm": VALID_QASM, "shots": 0, "backend": BACKEND},
    {"desc": "absurd shot count (10 million)", "qasm": VALID_QASM, "shots": 10_000_000, "backend": BACKEND},
    {"desc": "nonexistent backend name", "qasm": VALID_QASM, "shots": 64, "backend": "fake:nonexistent-backend-xyz"},
    {"desc": "empty QASM string", "qasm": "", "shots": 64, "backend": BACKEND},
]

class OpTimeout(Exception): pass
def _alarm_handler(s, f): raise OpTimeout()
def with_timeout(func, t, *a, **kw):
    old = signal.signal(signal.SIGALRM, _alarm_handler); signal.alarm(t)
    try: return func(*a, **kw)
    finally: signal.alarm(0); signal.signal(signal.SIGALRM, old)
def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    findings = []
    for case in TEST_CASES:
        print(f"--- {case['desc']} ---")
        try:
            jid = with_timeout(provider.submit_circuit, SUBMIT_TIMEOUT_S,
                                 case["qasm"], shots=case["shots"],
                                 backend=case["backend"], name=f"watchdog_fuzz_test")
            print(f"  ACCEPTED (unexpected for most of these): job_id={jid}")
            findings.append({"case": case["desc"], "accepted": True, "job_id": jid,
                               "error_text": None, "possible_stack_trace_leak": False})
        except OpTimeout:
            print(f"  Timed out (not a clean rejection)")
            findings.append({"case": case["desc"], "accepted": False, "job_id": None,
                               "error_text": "client-side timeout", "possible_stack_trace_leak": False})
        except Exception as e:
            err = str(e)
            looks_like_stack_trace = ("Traceback" in err or "File \"" in err
                                        or "line " in err and ".py" in err)
            print(f"  Rejected cleanly: {type(e).__name__}: {err[:200]}")
            if looks_like_stack_trace:
                print(f"  *** WARNING: error text looks like it may contain an internal stack trace ***")
            findings.append({"case": case["desc"], "accepted": False, "job_id": None,
                               "error_text": err[:500], "possible_stack_trace_leak": looks_like_stack_trace})
        time.sleep(2)

    accepted = [f for f in findings if f["accepted"]]
    trace_leaks = [f for f in findings if f.get("possible_stack_trace_leak")]

    print(f"\n{'='*60}")
    print(f"Malformed inputs incorrectly ACCEPTED: {len(accepted)}/{len(TEST_CASES)}")
    print(f"Error responses that may leak internal stack traces: {len(trace_leaks)}")
    print(f"{'='*60}")

    finding_summary = (
        f"Fuzzed {len(TEST_CASES)} malformed/extreme inputs (garbage QASM, negative/zero/"
        f"absurd shot counts, fake backend, empty circuit). {len(accepted)} were "
        f"incorrectly accepted rather than rejected. {len(trace_leaks)} error responses "
        f"showed patterns consistent with internal stack trace leakage. "
        f"{'Both are real findings worth reporting.' if (accepted or trace_leaks) else 'API handled all malformed input cleanly — no acceptance of invalid input, no apparent trace leakage.'}"
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"cases_tested": len(TEST_CASES), "incorrectly_accepted": len(accepted),
               "possible_trace_leaks": len(trace_leaks), "findings": findings,
               "finding_summary": finding_summary, "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module136_fuzzing_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("\nSaved.")
