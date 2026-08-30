"""
Module 96 — Quantum Random Number Generator (QRNG) Entropy Test (rebuilt)

METHOD:
  Submit a circuit that puts N qubits into equal superposition (H gate
  on each qubit, no entangling gates) and measures them. Ideal quantum
  randomness from this circuit should produce a near-uniform
  distribution across all 2^N bitstrings, with Shannon entropy close to
  N bits (the theoretical maximum for N qubits).

  Comparing the REAL measured entropy against this theoretical maximum
  is a direct, physics-grounded check of whether the QPU is producing
  genuine quantum randomness (as opposed to a biased, stuck, or
  classically-substituted source).

REBUILD NOTE (2026-08-08):
  The original module96.py could not be recovered from terminal
  scrollback (paste was repeatedly truncated to only the final ~8
  lines). This version is reconstructed from confirmed details in
  earlier tracebacks and output: function name run_qrng_test(),
  4096 shots, backend "rigetti:cepheus-1-108q", job name
  "watchdog_qrng_entropy_test", and the exact __main__ output block
  (OUTPUT_DIR, module96_qrng_entropy_result.json).

  If your original had different qubit count, entropy formula, or
  additional checks, diff this against your backup before relying on
  it — this rebuild is a best-effort reconstruction, not a byte-for-
  byte recovery of your original file.

  Same fix as module95: provider.submit_circuit() blocks internally on
  the SDK's own completion-wait loop, which has been dying with
  ConnectionAbortedError on this network. submit_circuit() is now
  called inside a bounded background thread with recovery-by-name from
  job history if it times out or errors, and status is polled manually
  with short, isolated calls afterward.
"""
import json
import time
import datetime
import math
import os
import signal
from quantum_providers import get_provider

SUBMIT_TIMEOUT_S = 25
POLL_MAX_WAIT_S = 180
POLL_INTERVAL_S = 8
NUM_QUBITS = 8
SHOTS = 4096


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def build_qrng_circuit(num_qubits=NUM_QUBITS):
    """N qubits, each put into equal superposition via H, then measured.
    No entangling gates — this isolates single-qubit randomness quality."""
    lines = ["OPENQASM 2.0;", 'include "qelib1.inc";',
             f"qreg q[{num_qubits}];", f"creg c[{num_qubits}];"]
    for i in range(num_qubits):
        lines.append(f"h q[{i}];")
    for i in range(num_qubits):
        lines.append(f"measure q[{i}] -> c[{i}];")
    return "\n".join(lines) + "\n"


def shannon_entropy(counts: dict, total_shots: int) -> float:
    """Shannon entropy in bits of the observed bitstring distribution."""
    entropy = 0.0
    for count in counts.values():
        if count <= 0:
            continue
        p = count / total_shots
        entropy -= p * math.log2(p)
    return entropy


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


def get_recent_job_ids(provider, limit=15):
    try:
        history = with_timeout(provider.get_job_history, 15, limit=limit)
        return {h.job_id for h in history}
    except OpTimeout:
        print(f"  [DEBUG] get_recent_job_ids TIMED OUT")
        return set()
    except Exception as e:
        print(f"  [DEBUG] get_recent_job_ids FAILED: {type(e).__name__}: {e}")
        return set()


def submit_with_recovery(provider, qasm, shots, backend, name,
                          submit_timeout=SUBMIT_TIMEOUT_S):
    known_job_ids = get_recent_job_ids(provider)
    print(f"  [DEBUG] baseline snapshot: {len(known_job_ids)} known job_ids")

    job_id = None
    try:
        job_id = with_timeout(
            provider.submit_circuit, submit_timeout,
            qasm, shots=shots, backend=backend, name=name
        )
        print(f"  [DEBUG] branch=CLEAN_SUCCESS  submitted cleanly: {job_id}")
        return job_id
    except OpTimeout:
        print(f"  [DEBUG] branch=TIMEOUT  exceeded {submit_timeout}s — "
              f"attempting recovery via history diff")
    except Exception as e:
        print(f"  [DEBUG] branch=EXCEPTION  {type(e).__name__}: {e} — "
              f"attempting recovery via history diff")

    time.sleep(3)
    current_job_ids = get_recent_job_ids(provider)
    new_ids = current_job_ids - known_job_ids
    print(f"  [DEBUG] history diff: {len(new_ids)} new job(s): "
          f"{[j[:8] for j in new_ids] if new_ids else '(none)'}")

    if len(new_ids) == 1:
        job_id = next(iter(new_ids))
        print(f"  [DEBUG] branch=RECOVERED_VIA_DIFF  job_id: {job_id}")
    elif len(new_ids) > 1:
        print(f"  [DEBUG] branch=RECOVERY_AMBIGUOUS  {len(new_ids)} new jobs")
    else:
        print(f"  [DEBUG] branch=RECOVERY_FAILED  no new job appeared")

    return job_id


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
        except Exception as e:
            print(f"  poll error ({type(e).__name__}) — will retry")
        time.sleep(poll_interval_s)

    print(f"  gave up after {max_wait_s}s, last known status: {last_status}")
    return last_status


def run_qrng_test(provider, shots=SHOTS):
    print(f"\n--- Submitting QRNG circuit ({shots} shots) ---")
    qasm = build_qrng_circuit(NUM_QUBITS)
    job_id = submit_with_recovery(provider, qasm, shots, "rigetti:cepheus-1-108q",
                                   "watchdog_qrng_entropy_test")
    print(f"QRNG job ID: {job_id}")

    print(f"\nPolling job (max {POLL_MAX_WAIT_S}s, {POLL_INTERVAL_S}s intervals)...")
    status = poll_job_status(provider, job_id)

    DONE_STATES = ("Completed", "Done")
    if status not in DONE_STATES:
        print(f"\n{'='*50}")
        print(f"INCOMPLETE — job did not finish within wait budget")
        print(f"Status: {status}  (job_id: {job_id})")
        print("Once OpenQuantum shows it Completed, pull results with:")
        print("  provider.get_job_results('<job_id>')")
        print(f"{'='*50}")
        return {
            "job_id": job_id, "status": status,
            "entropy_bits": None, "max_possible_entropy_bits": NUM_QUBITS,
            "entropy_ratio": None,
            "note": (f"Test incomplete — job did not reach Completed within "
                      f"the {POLL_MAX_WAIT_S}s wait budget. Re-run "
                      f"get_job_results manually with the saved job_id once "
                      f"status shows Completed."),
            "shots": shots, "num_qubits": NUM_QUBITS, "timestamp": now_iso(),
        }

    result = provider.get_job_results(job_id)
    counts = result.get("raw", {})
    total_shots = sum(counts.values())

    measured_entropy = shannon_entropy(counts, total_shots) if total_shots else 0.0
    max_entropy = NUM_QUBITS
    entropy_ratio = round(measured_entropy / max_entropy, 4) if max_entropy else 0.0

    print(f"\nCounts (top 10 by frequency): "
          f"{dict(sorted(counts.items(), key=lambda kv: -kv[1])[:10])}")
    print(f"Measured Shannon entropy: {measured_entropy:.4f} bits")
    print(f"Theoretical max entropy ({NUM_QUBITS} qubits): {max_entropy} bits")
    print(f"Entropy ratio: {entropy_ratio}")

    entropy_ok = entropy_ratio > 0.9  # arbitrary but reasonable "healthy" threshold

    print(f"\n{'='*50}")
    print(f"QRNG ENTROPY: {'HEALTHY' if entropy_ok else 'DEGRADED — INVESTIGATE'}")
    print(f"{'='*50}")

    return {
        "job_id": job_id, "status": status,
        "counts": counts, "total_shots": total_shots,
        "entropy_bits": round(measured_entropy, 4),
        "max_possible_entropy_bits": max_entropy,
        "entropy_ratio": entropy_ratio,
        "entropy_healthy": entropy_ok,
        "shots": shots, "num_qubits": NUM_QUBITS, "timestamp": now_iso(),
        "method": (f"{NUM_QUBITS} qubits placed in equal superposition via H "
                    f"gates (no entangling gates), measured, and the Shannon "
                    f"entropy of the resulting bitstring distribution compared "
                    f"against the theoretical maximum of {NUM_QUBITS} bits."),
    }


if __name__ == "__main__":
    provider = get_provider()
    print(f"Provider: {provider.provider_name}\n")

    result = run_qrng_test(provider)

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module96_qrng_entropy_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
