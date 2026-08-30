#!/usr/bin/env python3
"""
Watchdog — Module 97: Entanglement Fidelity Verification (Scoped) — repaired v2

HONEST SCOPING: this module does NOT perform full quantum state
tomography. Full tomography of even a single Bell pair requires
measuring in multiple non-commuting bases (typically 9 or more
measurement settings for 2 qubits, each with substantial shot counts)
to reconstruct the complete density matrix. That is a legitimate,
heavier procedure this module does not claim to do.

What this module DOES do: measures the prepared state in two
different bases (Z, X) rather than just the standard computational
(Z) basis used elsewhere in this suite. This gives a genuine,
mathematically-grounded LOWER BOUND on fidelity — stronger evidence
than a single-basis measurement, without the full cost of complete
tomography. This is a standard, real technique (a simplified
entanglement witness), not the maximal version, and this module says so
explicitly rather than calling it "tomography" to sound more impressive
than it is.

METHOD — CHSH-style basis rotation:
  1. Measure the Bell pair in the standard ZZ basis — gives
     P(00)+P(11) correlation.
  2. Measure in the XX basis (apply H to both qubits before
     measurement) — for a genuine |Phi+> Bell state, this should ALSO
     show strong correlation in 00/11.
  3. Combine both correlations into a fidelity LOWER BOUND using the
     standard two-basis entanglement witness formula:
     F >= P_ZZ(correlated) + P_XX(correlated) - 1
     (a real, published witness bound — not the full fidelity, a
     guaranteed minimum)

A state that passes the ZZ test alone but fails badly in the XX basis
would reveal itself as NOT a genuine Bell state (e.g. a classically
correlated mixture that only fakes correlation in one basis) — exactly
the kind of substitution attack a witness test like this is designed to
catch.

REPAIR NOTES (v2, 2026-08-08):
  Original called provider.submit_circuit() directly (blocking, same
  hang risk fixed in module95 v3/v4), then did a blind time.sleep(40)
  followed by get_job_results() with NO status check at all — if a job
  wasn't actually done after 40s, this would either crash or return
  garbage/incomplete data silently.

  v2 fix: same signal.alarm() timeout pattern as module95 v4 (no
  threads, no hang-on-exit risk), diff-based job recovery instead of
  name-matching (OpenQuantum's API doesn't return names — confirmed in
  module95 debugging), and a real bounded polling loop that checks
  actual job status before ever calling get_job_results(), instead of
  assuming 40 seconds is always enough.
"""
import json
import time
import datetime
import os
import signal
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 25
HISTORY_TIMEOUT_S = 15
POLL_MAX_WAIT_S = 180
POLL_INTERVAL_S = 8


class OpTimeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise OpTimeout()


def with_timeout(func, timeout_s, *args, **kwargs):
    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(timeout_s)
    try:
        return func(*args, **kwargs)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def build_bell_zz():
    """Standard basis — same as today's Bell state test."""
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""


def build_bell_xx():
    """
    Same Bell state, but measured in the X basis (H before measurement
    on both qubits). A genuine |Phi+> = (|00>+|11>)/sqrt(2) shows
    STRONG correlation here too — a classically-correlated fake would
    not.
    """
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
h q[0];
h q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""


def correlation_fraction(counts: dict, total: int) -> float:
    correlated = counts.get("00", 0) + counts.get("11", 0)
    return correlated / total if total else 0


def get_recent_job_ids(provider, limit=15):
    try:
        history = with_timeout(provider.get_job_history, HISTORY_TIMEOUT_S,
                                limit=limit)
        return {h.job_id for h in history}
    except OpTimeout:
        print(f"  [DEBUG] get_recent_job_ids TIMED OUT after {HISTORY_TIMEOUT_S}s")
        return set()
    except Exception as e:
        print(f"  [DEBUG] get_recent_job_ids FAILED: {type(e).__name__}: {e}")
        return set()


def submit_with_recovery(provider, qasm, shots, backend, name,
                          submit_timeout=SUBMIT_TIMEOUT_S,
                          known_job_ids=None):
    """No threads — signal.alarm timeout. Recovers job_id via
    before/after history diff (name-matching doesn't work — OpenQuantum
    never returns names, confirmed during module95 debugging)."""
    if known_job_ids is None:
        known_job_ids = get_recent_job_ids(provider)
        print(f"  [DEBUG] baseline snapshot: {len(known_job_ids)} known job_ids")

    job_id = None
    print(f"  [DEBUG] submit_with_recovery starting for name='{name}'")
    try:
        job_id = with_timeout(
            provider.submit_circuit, submit_timeout,
            qasm, shots=shots, backend=backend, name=name
        )
        print(f"  [DEBUG] branch=CLEAN_SUCCESS  submitted cleanly: {job_id}")
        known_job_ids = known_job_ids | {job_id}
        return job_id, known_job_ids
    except OpTimeout:
        print(f"  [DEBUG] branch=TIMEOUT  submit_circuit exceeded "
              f"{submit_timeout}s — attempting recovery via history diff")
    except Exception as e:
        print(f"  [DEBUG] branch=EXCEPTION  submit_circuit raised "
              f"{type(e).__name__}: {e} — attempting recovery via history diff")

    time.sleep(3)
    current_job_ids = get_recent_job_ids(provider)
    new_ids = current_job_ids - known_job_ids
    print(f"  [DEBUG] history diff: {len(current_job_ids)} jobs now visible, "
          f"{len(new_ids)} new since baseline: "
          f"{[j[:8] for j in new_ids] if new_ids else '(none)'}")

    if len(new_ids) == 1:
        job_id = next(iter(new_ids))
        print(f"  [DEBUG] branch=RECOVERED_VIA_DIFF  exactly one new job_id: {job_id}")
        known_job_ids = current_job_ids
    elif len(new_ids) > 1:
        print(f"  [DEBUG] branch=RECOVERY_AMBIGUOUS  {len(new_ids)} new jobs — "
              f"cannot tell which is '{name}': {[j[:8] for j in new_ids]}")
        known_job_ids = current_job_ids
    else:
        print(f"  [DEBUG] branch=RECOVERY_FAILED  no new job_id since baseline")

    return job_id, known_job_ids


def poll_job_status(provider, job_id, max_wait_s=POLL_MAX_WAIT_S,
                     poll_interval_s=POLL_INTERVAL_S):
    if job_id is None:
        return "UNKNOWN"
    start = time.time()
    last_status = "UNKNOWN"
    while time.time() - start < max_wait_s:
        try:
            job = with_timeout(provider._scheduler.get_job, 15, job_id)
            last_status = job.status
            print(f"  status: {last_status} ({int(time.time() - start)}s elapsed)")
            if last_status in ("Completed", "Done", "FAILED", "Cancelled", "Error"):
                return last_status
        except OpTimeout:
            print(f"  poll timed out after 15s — will retry")
        except Exception as e:
            print(f"  poll error ({type(e).__name__}) — will retry")
        time.sleep(poll_interval_s)
    print(f"  gave up after {max_wait_s}s, last known status: {last_status}")
    return last_status


def run_fidelity_witness_test(provider, shots=2048):
    print("--- Submitting Bell state, ZZ basis (standard) ---")
    zz_qasm = build_bell_zz()
    zz_job, known_ids = submit_with_recovery(
        provider, zz_qasm, shots, "rigetti:cepheus-1-108q", "watchdog_fidelity_witness_zz")
    print(f"ZZ job ID: {zz_job}")

    print("\n--- Submitting Bell state, XX basis (witness) ---")
    xx_qasm = build_bell_xx()
    xx_job, known_ids = submit_with_recovery(
        provider, xx_qasm, shots, "rigetti:cepheus-1-108q", "watchdog_fidelity_witness_xx",
        known_job_ids=known_ids)
    print(f"XX job ID: {xx_job}")

    print(f"\nPolling both jobs (max {POLL_MAX_WAIT_S}s each)...")
    print("ZZ:")
    zz_status = poll_job_status(provider, zz_job)
    print("XX:")
    xx_status = poll_job_status(provider, xx_job)

    DONE_STATES = ("Completed", "Done")
    if zz_status not in DONE_STATES or xx_status not in DONE_STATES:
        print(f"\n{'='*50}")
        print("INCOMPLETE — one or both jobs did not finish within the wait budget")
        print(f"ZZ status: {zz_status}  (job_id: {zz_job})")
        print(f"XX status: {xx_status}  (job_id: {xx_job})")
        print(f"{'='*50}")
        return {
            "zz_job_id": zz_job, "zz_status": zz_status,
            "xx_job_id": xx_job, "xx_status": xx_status,
            "fidelity_lower_bound": None,
            "genuinely_entangled_witness_passed": None,
            "note": ("Test incomplete within wait budget. Re-run get_job_results "
                      "manually using the saved job IDs once status shows Completed."),
            "shots_per_basis": shots, "timestamp": now_iso(),
        }

    zz_result = provider.get_job_results(zz_job)
    zz_counts = zz_result.get("raw", {})
    zz_total = sum(zz_counts.values())
    p_zz = correlation_fraction(zz_counts, zz_total)

    xx_result = provider.get_job_results(xx_job)
    xx_counts = xx_result.get("raw", {})
    xx_total = sum(xx_counts.values())
    p_xx = correlation_fraction(xx_counts, xx_total)

    print(f"\nZZ counts: {zz_counts}")
    print(f"P(correlated in ZZ basis): {p_zz:.4f}")
    print(f"\nXX counts: {xx_counts}")
    print(f"P(correlated in XX basis): {p_xx:.4f}")

    fidelity_lower_bound = max(0.0, p_zz + p_xx - 1.0)

    print(f"\n{'='*50}")
    print(f"Fidelity LOWER BOUND (2-basis witness): {fidelity_lower_bound:.4f}")
    print(f"(This is a guaranteed minimum, not the true fidelity — the")
    print(f" real fidelity is >= this value.)")
    print(f"{'='*50}")

    is_genuinely_entangled = fidelity_lower_bound > 0.5

    return {
        "zz_job_id": zz_job, "zz_counts": zz_counts, "p_zz_correlated": p_zz,
        "xx_job_id": xx_job, "xx_counts": xx_counts, "p_xx_correlated": p_xx,
        "fidelity_lower_bound": fidelity_lower_bound,
        "genuinely_entangled_witness_passed": is_genuinely_entangled,
        "shots_per_basis": shots, "timestamp": now_iso(),
        "scope_honesty": ("This is a 2-basis entanglement witness giving a "
                            "fidelity LOWER BOUND, not full quantum state "
                            "tomography."),
    }


if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    result = run_fidelity_witness_test(provider)

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module97_fidelity_witness_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
