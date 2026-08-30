"""
Module 95 — Fault Injection Pipeline Integrity Test (repaired, v4)

METHOD:
  1. Submit the known-correct circuit (e.g. a Bell state) — this is the
     control, and its expected output is mathematically known.
  2. Separately submit the SAME circuit with one deliberate extra gate
     inserted (e.g. an extra X gate on one qubit) — the "corrupted"
     variant, whose expected output is ALSO mathematically known and
     different from the control.
  3. Compare both real results against their respective mathematical
     predictions.
  4. If the control circuit's result does NOT match its prediction, but
     instead resembles the corrupted variant's prediction (or vice
     versa), that is direct evidence something altered the circuit
     between submission and execution — the two are cleanly
     distinguishable by design.

This is a PIPELINE INTEGRITY test, using the QPU's own real physics as
the detector — not a hardware-noise test.

REPAIR NOTES (v3, 2026-08-08):
  v2 wrapped provider.submit_circuit() in a background thread with a
  timeout via concurrent.futures. That masked the SYMPTOM (the call
  never returning) but not the underlying problem: when the `with
  ThreadPoolExecutor(...)` block exits, Python unconditionally waits
  for the background thread to finish (thread.join()) before
  continuing — even after future.result(timeout=...) already gave up.
  If the thread is stuck inside a dead network call, the ENTIRE SCRIPT
  hangs silently at that exit point, with no output and no way out
  except Ctrl+C. This is what was actually happening — not a timeout
  that was too short, but a timeout that didn't actually free the
  script from the thread.

  v3 fix: no threads at all. Uses signal.alarm() (Linux only — fine
  here since we're in Termux/proot Ubuntu) to forcibly interrupt a
  hung call directly in the main thread. This cannot leave a stray
  thread blocking script exit, because there is no separate thread.

  v4 fix: v3's history-recovery matched by 'name', but a real run
  confirmed every job history entry returns name=None — OpenQuantum's
  API simply does not return job names at all, so name-matching could
  never have worked regardless of timeout tuning. v4 instead takes a
  snapshot of known job_ids BEFORE each submission attempt, and after
  a timeout/exception, diffs the current job list against that
  snapshot — whichever job_id is NEW is the one just created. This is
  threaded sequentially: control's snapshot is taken first, and after
  control resolves, injected's recovery diffs against the UPDATED set
  (including control's job_id), so control's own recovery can't be
  mistaken for injected's.
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
    """Run func(*args, **kwargs) with a hard wall-clock timeout using
    SIGALRM. Raises OpTimeout if it doesn't return in time. Unlike a
    background thread, this cannot leave anything hanging on exit —
    there is no separate thread to wait for."""
    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(timeout_s)
    try:
        return func(*args, **kwargs)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def build_bell_control():
    return """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""


def build_bell_injected(injection_type="extra_x"):
    if injection_type == "extra_x":
        qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
x q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""
        expected_dominant = ["01", "10"]
    elif injection_type == "extra_h":
        qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
h q[0];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""
        expected_dominant = ["00", "01", "10", "11"]
    else:
        raise ValueError(f"unknown injection_type: {injection_type}")
    return qasm, expected_dominant


def classify_result(counts: dict, dominant_states: list, total_shots: int) -> dict:
    dominant_count = sum(counts.get(s, 0) for s in dominant_states)
    fraction = dominant_count / total_shots if total_shots else 0
    return {"dominant_states": dominant_states,
             "dominant_fraction": round(fraction, 4),
             "matches_prediction": fraction > 0.7}


def get_recent_job_ids(provider, limit=15):
    """Returns the set of job_ids currently visible in job history.
    Timeout-protected so a hung call here can't hang the whole script."""
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
    """No threads. submit_circuit() runs directly in the main thread
    under a signal.alarm() timeout. If it doesn't return in time, or
    raises, we recover the job_id by diffing job history against a
    'before' snapshot (known_job_ids) instead of matching by name —
    OpenQuantum's API does not return job names in history, confirmed
    by every history entry showing name=None in prior runs, so
    name-matching could never have worked. Whichever job_id is NEW
    since the snapshot is the one this call just created.

    Returns (job_id, updated_known_job_ids) — the caller must thread
    known_job_ids through sequential calls so each one's diff is
    against the state right before IT submitted, not before the first
    submission of the run."""
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
              f"{submit_timeout}s — abandoning wait, attempting recovery "
              f"via history diff")
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
        print(f"  [DEBUG] branch=RECOVERY_AMBIGUOUS  {len(new_ids)} new jobs "
              f"appeared since baseline — cannot tell which one is '{name}' "
              f"without a reliable name field. Job IDs: {[j[:8] for j in new_ids]}")
        known_job_ids = current_job_ids
    else:
        print(f"  [DEBUG] branch=RECOVERY_FAILED  no new job_id appeared since "
              f"baseline — submission likely never reached OpenQuantum at all")

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


def run_injection_test(provider, shots=1024):
    print("--- Submitting CONTROL circuit (Bell state, unmodified) ---")
    control_qasm = build_bell_control()
    control_job, known_ids = submit_with_recovery(
        provider, control_qasm, shots, "rigetti:cepheus-1-108q",
        "watchdog_fault_injection_control")
    print(f"Control job ID: {control_job}")

    print("\n--- Submitting INJECTED circuit (Bell state + extra X gate) ---")
    injected_qasm, expected_dominant = build_bell_injected("extra_x")
    injected_job, known_ids = submit_with_recovery(
        provider, injected_qasm, shots, "rigetti:cepheus-1-108q",
        "watchdog_fault_injection_test", known_job_ids=known_ids)
    print(f"Injected job ID: {injected_job}")

    print(f"\nPolling both jobs (max {POLL_MAX_WAIT_S}s each, "
          f"{POLL_INTERVAL_S}s intervals)...")
    print("Control:")
    control_status = poll_job_status(provider, control_job)
    print("Injected:")
    injected_status = poll_job_status(provider, injected_job)

    DONE_STATES = ("Completed", "Done")
    if control_status not in DONE_STATES or injected_status not in DONE_STATES:
        print(f"\n{'='*50}")
        print("INCOMPLETE — one or both jobs did not finish within the wait budget")
        print(f"Control status:  {control_status}  (job_id: {control_job})")
        print(f"Injected status: {injected_status}  (job_id: {injected_job})")
        print(f"{'='*50}")
        return {
            "control_job_id": control_job, "control_status": control_status,
            "injected_job_id": injected_job, "injected_status": injected_status,
            "pipeline_integrity_confirmed": None,
            "note": ("Test incomplete within wait budget. Re-run get_job_results "
                      "manually using the saved job IDs once status shows Completed."),
            "shots": shots, "timestamp": now_iso(),
        }

    control_result = provider.get_job_results(control_job)
    control_counts = control_result.get("raw", {})
    control_total = sum(control_counts.values())
    control_check = classify_result(control_counts, ["00", "11"], control_total)

    injected_result = provider.get_job_results(injected_job)
    injected_counts = injected_result.get("raw", {})
    injected_total = sum(injected_counts.values())
    injected_check = classify_result(injected_counts, expected_dominant, injected_total)

    print(f"\nControl counts: {control_counts}")
    print(f"Control matches Bell prediction (00/11 dominant): {control_check['matches_prediction']}")
    print(f"\nInjected counts: {injected_counts}")
    print(f"Injected matches corrupted prediction (01/10 dominant): {injected_check['matches_prediction']}")

    pipeline_integrity_ok = (control_check["matches_prediction"]
                             and injected_check["matches_prediction"])

    print(f"\n{'='*50}")
    print(f"PIPELINE INTEGRITY: {'CONFIRMED' if pipeline_integrity_ok else 'FAILED — INVESTIGATE'}")
    print(f"{'='*50}")

    return {
        "control_job_id": control_job, "control_counts": control_counts,
        "control_check": control_check,
        "injected_job_id": injected_job, "injected_counts": injected_counts,
        "injected_check": injected_check,
        "pipeline_integrity_confirmed": pipeline_integrity_ok,
        "shots": shots, "timestamp": now_iso(),
    }


if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    result = run_injection_test(provider)

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module95_fault_injection_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
