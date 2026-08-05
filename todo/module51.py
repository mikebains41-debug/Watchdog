#!/usr/bin/env python3
"""
Watchdog — Module 51: Circuit Result Verification

Attack vector: module33 hashes the circuit going IN. Nothing verifies the
results coming OUT are genuinely from the QPU. An attacker who compromises
the API path — or a dishonest provider — could return plausible-looking
fabricated results, classically-simulated results, or results from a
cheaper/degraded backend than the one billed.

Method: submit known-answer circuits at intervals and verify the returned
distribution matches quantum-mechanical expectation within statistical
tolerance. Real hardware has characteristic noise. Fabricated results and
noiseless classical simulation both fail differently:

  - Bell state |Φ+>: expect ~50% |00>, ~50% |11>, small |01>/|10> from noise.
    Zero |01>/|10> counts = suspiciously noiseless (simulator, not hardware).
    Uniform across all four = fabricated or wrong circuit executed.

  - GHZ state (3-qubit): expect ~50% |000>, ~50% |111>.
    Same logic, tighter — more qubits means more real hardware noise.

Statistical test: chi-squared goodness of fit against expected distribution,
plus an explicit noise-floor check (real QPUs are never noiseless).

Requires: qiskit-ibm-runtime
Credentials: IBM_QUANTUM_TOKEN env var
"""
import json, datetime, os, time, math, hashlib
from collections import deque

PROBE_INTERVAL     = 3600    # seconds between verification probes
PROBE_SHOTS        = 4096    # shots per probe — enough for stable statistics
CHI2_THRESHOLD     = 30.0    # chi-squared above this = distribution mismatch
NOISE_FLOOR_MIN    = 0.002   # min fraction in "forbidden" states — real HW is noisy
NOISE_FLOOR_MAX    = 0.15    # max — above this the backend is badly degraded
BELL_TOLERANCE     = 0.15    # |00> and |11> should each be 0.5 +/- this
HISTORY_FILE       = "/tmp/watchdog_result_verification.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_history() -> dict:
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)
    except:
        return {"probes": [], "chi2_history": []}

def save_history(h: dict):
    try:
        h["probes"] = h.get("probes", [])[-100:]
        h["chi2_history"] = h.get("chi2_history", [])[-100:]
        with open(HISTORY_FILE, "w") as f:
            json.dump(h, f)
    except:
        pass

def chi_squared(observed: dict, expected: dict, total: int) -> float:
    """
    Pearson chi-squared goodness of fit.
    observed/expected are bitstring -> count / bitstring -> probability.
    """
    chi2 = 0.0
    all_keys = set(observed) | set(expected)
    for key in all_keys:
        obs = observed.get(key, 0)
        exp = expected.get(key, 0.0) * total
        if exp > 0:
            chi2 += ((obs - exp) ** 2) / exp
        elif obs > 0:
            # Observed counts in a state with zero expected probability.
            # Real hardware noise puts a small number here, so treat the
            # expected value as the noise floor rather than dividing by zero.
            floor = NOISE_FLOOR_MIN * total
            chi2 += ((obs - floor) ** 2) / max(floor, 1.0)
    return chi2

def bell_expected() -> dict:
    """Ideal Bell state |Phi+> = (|00> + |11>)/sqrt(2)."""
    return {"00": 0.5, "11": 0.5}

def ghz_expected() -> dict:
    """Ideal 3-qubit GHZ = (|000> + |111>)/sqrt(2)."""
    return {"000": 0.5, "111": 0.5}

def analyse_distribution(counts: dict, expected: dict, shots: int,
                          label: str) -> list:
    """
    Returns a list of alert dicts. Checks three independent things:
      1. Chi-squared fit against the expected quantum distribution
      2. Noise floor — real QPUs always show some population in
         states the ideal circuit forbids
      3. Balance between the two dominant states
    """
    alerts = []

    total = sum(counts.values())
    if total == 0:
        return [{"event": "RESULT_EMPTY", "severity": "WARN",
                  "probe": label, "note": "Zero counts returned"}]

    # ── 1. Chi-squared goodness of fit ──
    chi2 = chi_squared(counts, expected, total)
    if chi2 > CHI2_THRESHOLD:
        alerts.append({
            "event":    "RESULT_DISTRIBUTION_MISMATCH",
            "severity": "CRITICAL",
            "probe":    label,
            "chi2":     round(chi2, 2),
            "threshold": CHI2_THRESHOLD,
            "observed": dict(sorted(counts.items(), key=lambda x: -x[1])[:8]),
            "expected": expected,
            "confidence": 0.85,
            "note": ("Returned distribution does not match quantum expectation — "
                     "possible fabricated results or wrong circuit executed"),
        })

    # ── 2. Noise floor check ──
    forbidden_count = sum(c for k, c in counts.items() if k not in expected)
    noise_fraction  = forbidden_count / total

    if noise_fraction < NOISE_FLOOR_MIN:
        alerts.append({
            "event":    "RESULT_SUSPICIOUSLY_NOISELESS",
            "severity": "CRITICAL",
            "probe":    label,
            "noise_fraction": round(noise_fraction, 5),
            "floor":    NOISE_FLOOR_MIN,
            "confidence": 0.90,
            "note": ("Results are cleaner than any real QPU produces — "
                     "consistent with classical simulation being returned "
                     "instead of hardware execution"),
        })
    elif noise_fraction > NOISE_FLOOR_MAX:
        alerts.append({
            "event":    "RESULT_EXCESSIVE_NOISE",
            "severity": "WARN",
            "probe":    label,
            "noise_fraction": round(noise_fraction, 4),
            "ceiling":  NOISE_FLOOR_MAX,
            "confidence": 0.70,
            "note": ("Noise far above expected for a calibrated backend — "
                     "degraded hardware, or job routed to a worse QPU than billed"),
        })

    # ── 3. Balance between the two dominant states ──
    keys = list(expected.keys())
    if len(keys) == 2:
        a = counts.get(keys[0], 0) / total
        b = counts.get(keys[1], 0) / total
        if abs(a - 0.5) > BELL_TOLERANCE or abs(b - 0.5) > BELL_TOLERANCE:
            alerts.append({
                "event":    "RESULT_STATE_IMBALANCE",
                "severity": "WARN",
                "probe":    label,
                keys[0]:    round(a, 4),
                keys[1]:    round(b, 4),
                "tolerance": BELL_TOLERANCE,
                "confidence": 0.65,
                "note": ("Entangled state populations badly imbalanced — "
                         "readout bias, calibration drift, or tampering"),
            })

    return alerts, chi2, noise_fraction

def run_probe(token: str, backend_name: str | None, probe: str):
    """
    Submit a known-answer circuit and return its measured counts.
    probe: "bell" (2-qubit) or "ghz" (3-qubit)
    """
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler
        from qiskit import QuantumCircuit, transpile

        svc = QiskitRuntimeService(token=token)
        backend = (svc.backend(backend_name) if backend_name
                   else svc.least_busy(operational=True, simulator=False,
                                        min_num_qubits=3))

        if probe == "bell":
            qc = QuantumCircuit(2)
            qc.h(0)
            qc.cx(0, 1)
        else:   # ghz
            qc = QuantumCircuit(3)
            qc.h(0)
            qc.cx(0, 1)
            qc.cx(0, 2)
        qc.measure_all()

        qc_t = transpile(qc, backend=backend, optimization_level=1)

        sampler = Sampler(backend)
        job     = sampler.run([qc_t], shots=PROBE_SHOTS)
        result  = job.result()

        # Extract counts across Qiskit result shapes
        counts = {}
        try:
            pub = result[0]
            data = pub.data
            for field in dir(data):
                if field.startswith("_"):
                    continue
                obj = getattr(data, field)
                if hasattr(obj, "get_counts"):
                    counts = obj.get_counts()
                    break
        except Exception:
            pass

        # Normalise keys — strip spaces Qiskit inserts for registers
        counts = {k.replace(" ", ""): v for k, v in counts.items()}

        return {
            "counts":  counts,
            "backend": backend.name,
            "job_id":  job.job_id(),
            "shots":   PROBE_SHOTS,
            "probe":   probe,
        }
    except ImportError:
        return {"error": "qiskit_ibm_runtime not installed"}
    except Exception as e:
        return {"error": str(e)}

def main():
    token   = os.environ.get("IBM_QUANTUM_TOKEN")
    backend = os.environ.get("IBM_QUANTUM_BACKEND")
    log     = open(f"module51_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "51_result_verification",
          "probes": ["bell", "ghz"],
          "shots_per_probe": PROBE_SHOTS,
          "chi2_threshold": CHI2_THRESHOLD,
          "noise_floor": [NOISE_FLOOR_MIN, NOISE_FLOOR_MAX],
          "credentials": "present" if token else "absent"})

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set IBM_QUANTUM_TOKEN to enable result verification probes"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    history = load_history()
    alerts  = 0

    while True:
        for probe, expected_fn in (("bell", bell_expected), ("ghz", ghz_expected)):
            result = run_probe(token, backend, probe)

            if "error" in result:
                emit({"event": "PROBE_ERROR", "probe": probe,
                      "detail": result["error"]})
                continue

            counts   = result["counts"]
            expected = expected_fn()

            analysis = analyse_distribution(counts, expected,
                                             PROBE_SHOTS, probe)
            if isinstance(analysis, list):
                probe_alerts, chi2, noise = analysis, None, None
            else:
                probe_alerts, chi2, noise = analysis

            emit({"event":   "PROBE_COMPLETE",
                  "probe":   probe,
                  "backend": result["backend"],
                  "job_id":  result["job_id"],
                  "chi2":    round(chi2, 2) if chi2 is not None else None,
                  "noise_fraction": round(noise, 5) if noise is not None else None,
                  "top_states": dict(sorted(counts.items(),
                                             key=lambda x: -x[1])[:4])})

            for a in probe_alerts:
                alerts += 1
                emit(a)

            history["probes"].append({
                "probe": probe, "chi2": chi2,
                "noise": noise, "ts": now_iso()
            })
            if chi2 is not None:
                history["chi2_history"].append(chi2)

            save_history(history)

        time.sleep(PROBE_INTERVAL)

if __name__ == "__main__":
    main()
