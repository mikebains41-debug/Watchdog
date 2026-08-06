#!/usr/bin/env python3
"""
Watchdog — Module 69: Readout Crosstalk Leak Detector
Status: FUNCTIONAL with IBM_QUANTUM_TOKEN

PUBLISHED ATTACK THIS MODULE DEFENDS AGAINST:

  "I Know What You Are Reading: Evaluating Readout Crosstalk in
  Cloud-based Quantum Computers." Proceedings of the 2025 Quantum
  Security and Privacy Workshop (ACM). DOI 10.1145/3733825.3765280.

  The attack: an adversary co-located on the same QPU runs a
  MEASUREMENT-ONLY circuit — no gates, no computation, just measurement
  — positioned near a victim. Readout crosstalk between the measurement
  resonators leaks the victim's state into the attacker's results. The
  paper demonstrates an end-to-end attack against a victim running a
  2-qubit Grover's algorithm, after first reconstructing the hardware
  mapping from observable behaviour.

  Bell, B. & Trügler, A. "Reconstructing quantum circuits through
  side-channel information on cloud-based superconducting quantum
  computers." IEEE QCE 2022, pp. 259-264.

WHY READOUT IS DIFFERENT: module66 watches gate-error crosstalk — the
signature of an attacker running entangling gates. This is a distinct
channel. Readout crosstalk requires no gates at all. An attacker circuit
consisting solely of measurement instructions is computationally trivial,
cheap to run, and looks like nothing on any usage report. It is the
lowest-cost attack in the multi-tenant literature.

The physical mechanism: superconducting qubits are read out by probing
their coupled resonators. Resonators are frequency-multiplexed onto
shared feedlines. When two resonators sit close in frequency, the
measurement tone for one perturbs the other, and the discrimination
between |0> and |1> on one qubit becomes conditioned on the state of
its neighbour.

WHAT THIS MODULE DOES:
  1. Measures readout crosstalk directly with a correlation experiment:
     prepare one qubit in |1>, leave its neighbours in |0>, measure all,
     and see whether the neighbours' readout is biased by the prepared
     qubit's state. Repeated across the allocation.
  2. Compares each qubit's measured readout error against its calibrated
     readout error from backend.properties(). A gap between the two is
     interference the calibration does not account for.
  3. Detects asymmetric readout error — P(read 1 | prepared 0) far from
     P(read 0 | prepared 1). Asymmetry is a hallmark of a neighbouring
     measurement tone pulling the discriminator threshold.
  4. Tracks readout error against QPU queue depth over time. Readout
     fidelity that degrades when the machine is busy is co-tenancy
     interference, not device drift.
  5. Flags qubits whose measured conditional correlation exceeds the
     threshold at which the published attack becomes viable.

Requires: qiskit, qiskit-ibm-runtime
Credentials: IBM_QUANTUM_TOKEN
"""
import json, os, time, datetime, math
from collections import defaultdict

POLL_INTERVAL          = 3600    # seconds between measurement campaigns
PROBE_SHOTS            = 2048    # shots per correlation experiment
CORRELATION_THRESHOLD  = 0.05    # conditional bias above this = leak
ASYMMETRY_THRESHOLD    = 0.03    # |P(1|0) - P(0|1)| above this = asymmetric
CALIBRATION_GAP_MULT   = 2.0     # measured error > this x calibrated = gap
QUEUE_CORRELATION_MIN  = 0.50    # Pearson r vs queue depth
HISTORY_SIZE           = 30
STATE_FILE             = "/tmp/watchdog_readout_crosstalk.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"history": [], "established": now_iso()}

def save_state(s: dict):
    try:
        s["history"] = s.get("history", [])[-HISTORY_SIZE:]
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def pearson(xs: list, ys: list) -> float | None:
    n = len(xs)
    if n < 3 or len(ys) != n:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx  = math.sqrt(sum((x - mx) ** 2 for x in xs))
    dy  = math.sqrt(sum((y - my) ** 2 for y in ys))
    if dx == 0 or dy == 0:
        return None
    return num / (dx * dy)

def extract_counts(result) -> dict:
    """Pull measurement counts out of a Qiskit result across API shapes."""
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
    return {k.replace(" ", ""): v for k, v in counts.items()}

def run_correlation_probe(token: str, backend_name: str | None,
                           target_qubit: int, neighbours: list) -> dict:
    """
    The core measurement. Two circuits on the same physical qubits:

      Circuit A: all qubits prepared in |0>, all measured.
      Circuit B: target prepared in |1> (X gate), neighbours left in |0>,
                 all measured.

    If readout is clean, the neighbours read 0 with equal probability in
    both circuits. If the target's measurement tone leaks into a
    neighbour's resonator, the neighbour's error rate changes between A
    and B. That difference IS the readout crosstalk, measured directly.
    """
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler
        from qiskit import QuantumCircuit, transpile

        svc = QiskitRuntimeService(token=token)
        backend = (svc.backend(backend_name) if backend_name
                   else svc.least_busy(operational=True, simulator=False,
                                        min_num_qubits=5))

        all_q = [target_qubit] + list(neighbours)
        n     = len(all_q)

        # Circuit A — everything in |0>
        qc_a = QuantumCircuit(n)
        qc_a.measure_all()

        # Circuit B — target in |1>, neighbours in |0>
        qc_b = QuantumCircuit(n)
        qc_b.x(0)          # index 0 maps to target_qubit via initial_layout
        qc_b.measure_all()

        ta = transpile(qc_a, backend=backend, initial_layout=all_q,
                       optimization_level=0)
        tb = transpile(qc_b, backend=backend, initial_layout=all_q,
                       optimization_level=0)

        sampler = Sampler(backend)
        job = sampler.run([ta, tb], shots=PROBE_SHOTS)
        result = job.result()

        counts_a = extract_counts([result[0]])
        counts_b = extract_counts([result[1]])

        status = backend.status()

        return {
            "backend":      backend.name,
            "target":       target_qubit,
            "neighbours":   list(neighbours),
            "counts_zero":  counts_a,
            "counts_excited": counts_b,
            "shots":        PROBE_SHOTS,
            "queue_depth":  status.pending_jobs,
            "job_id":       job.job_id(),
        }
    except ImportError:
        return {"error": "qiskit_ibm_runtime not installed"}
    except Exception as e:
        return {"error": str(e)}

def neighbour_error_rate(counts: dict, neighbour_index: int,
                          n_qubits: int, shots: int) -> float | None:
    """
    Fraction of shots where a given neighbour read 1 when it should
    have read 0. Bitstrings are little-endian in Qiskit: index 0 is the
    rightmost character.
    """
    if not counts:
        return None
    wrong = 0
    total = 0
    for bitstring, c in counts.items():
        bits = bitstring.replace(" ", "")
        if len(bits) < n_qubits:
            continue
        # Qiskit bitstrings are reversed relative to qubit index
        bit = bits[len(bits) - 1 - neighbour_index]
        total += c
        if bit == "1":
            wrong += c
    return (wrong / total) if total else None

def analyse_probe(probe: dict, calibrated: dict) -> list:
    """
    Compare neighbour error rates between the |0> and |1> preparations.
    A difference is direct evidence of readout crosstalk.
    """
    alerts = []
    if "error" in probe:
        return alerts

    n_qubits   = 1 + len(probe.get("neighbours", []))
    shots      = probe.get("shots", PROBE_SHOTS)
    target     = probe.get("target")
    backend    = probe.get("backend")

    for idx, nq in enumerate(probe.get("neighbours", []), start=1):
        err_zero    = neighbour_error_rate(probe["counts_zero"], idx,
                                            n_qubits, shots)
        err_excited = neighbour_error_rate(probe["counts_excited"], idx,
                                            n_qubits, shots)
        if err_zero is None or err_excited is None:
            continue

        # The crosstalk figure: how much does this neighbour's readout
        # change purely because the target was prepared in |1>?
        delta = abs(err_excited - err_zero)

        if delta > CORRELATION_THRESHOLD:
            alerts.append({
                "event":    "READOUT_CROSSTALK_LEAK",
                "severity": "CRITICAL",
                "backend":  backend,
                "target_qubit":    target,
                "leaking_qubit":   nq,
                "error_when_target_zero":    round(err_zero, 5),
                "error_when_target_excited": round(err_excited, 5),
                "conditional_bias":          round(delta, 5),
                "threshold": CORRELATION_THRESHOLD,
                "shots":     shots,
                "confidence": 0.85,
                "citation": ("ACM Quantum Security and Privacy Workshop 2025, "
                              "DOI 10.1145/3733825.3765280"),
                "note": (f"Qubit {nq} readout is conditioned on the state of "
                         f"qubit {target} at {round(delta*100, 2)}%. A "
                         "measurement-only attacker circuit placed on qubit "
                         f"{nq} recovers information about qubit {target} "
                         "without running a single gate. This is the exact "
                         "channel used in the published end-to-end attack "
                         "against a 2-qubit Grover victim"),
            })

        # Calibrated vs measured gap
        cal = calibrated.get(nq) or calibrated.get(str(nq))
        if cal is not None and cal > 0:
            measured = max(err_zero, err_excited)
            if measured > cal * CALIBRATION_GAP_MULT:
                alerts.append({
                    "event":    "READOUT_CALIBRATION_GAP",
                    "severity": "WARN",
                    "backend":  backend,
                    "qubit":    nq,
                    "calibrated_error": round(cal, 5),
                    "measured_error":   round(measured, 5),
                    "ratio":    round(measured / cal, 2),
                    "confidence": 0.65,
                    "note": ("Measured readout error is well above the value "
                             "backend.properties() reports. The calibration "
                             "does not account for whatever is interfering "
                             "with this qubit's readout right now"),
                })

    # Asymmetry check on the target itself
    err_t_zero    = neighbour_error_rate(probe["counts_zero"], 0,
                                          n_qubits, shots)
    err_t_excited = neighbour_error_rate(probe["counts_excited"], 0,
                                          n_qubits, shots)
    if err_t_zero is not None and err_t_excited is not None:
        p_1_given_0 = err_t_zero
        p_0_given_1 = 1.0 - err_t_excited
        asym = abs(p_1_given_0 - p_0_given_1)
        if asym > ASYMMETRY_THRESHOLD:
            alerts.append({
                "event":    "READOUT_ASYMMETRY",
                "severity": "WARN",
                "backend":  backend,
                "qubit":    target,
                "p_read1_given_prep0": round(p_1_given_0, 5),
                "p_read0_given_prep1": round(p_0_given_1, 5),
                "asymmetry": round(asym, 5),
                "threshold": ASYMMETRY_THRESHOLD,
                "confidence": 0.60,
                "citation": "IEEE QCE 2022, Bell & Trügler, pp. 259-264",
                "note": ("Readout error is asymmetric between the two "
                         "preparations. A neighbouring measurement tone "
                         "pulling the |0>/|1> discriminator threshold "
                         "produces exactly this signature"),
            })

    return alerts

def analyse_history(state: dict) -> list:
    """Does readout fidelity track how busy the machine is?"""
    alerts  = []
    history = state.get("history", [])
    if len(history) < 8:
        return alerts

    queue  = [h.get("queue_depth", 0) for h in history]
    by_q   = defaultdict(list)
    for h in history:
        for qubit, err in (h.get("errors") or {}).items():
            by_q[qubit].append(err)

    for qubit, series in by_q.items():
        if len(series) != len(queue):
            continue
        if all(s == series[0] for s in series):
            continue
        r = pearson(queue, series)
        if r is not None and r >= QUEUE_CORRELATION_MIN:
            alerts.append({
                "event":    "READOUT_QUEUE_CORRELATION",
                "severity": "WARN",
                "qubit":    qubit,
                "pearson_r": round(r, 3),
                "threshold": QUEUE_CORRELATION_MIN,
                "samples":  len(series),
                "confidence": 0.65,
                "note": (f"Readout error on qubit {qubit} correlates with QPU "
                         f"queue depth at r={round(r, 3)}. Readout fidelity "
                         "should be a property of the device, not of how many "
                         "other tenants are on it"),
            })
            break

    return alerts

def pick_probe_targets(token: str, backend_name: str | None) -> dict | None:
    """
    Choose a target qubit and its coupled neighbours to probe, plus
    pull the calibrated readout errors for comparison.
    """
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        svc = QiskitRuntimeService(token=token)
        backend = (svc.backend(backend_name) if backend_name
                   else svc.least_busy(operational=True, simulator=False,
                                        min_num_qubits=5))
        props = backend.properties(refresh=True)

        adj = defaultdict(set)
        try:
            cm = backend.coupling_map
            if cm is not None:
                for a, b in cm:
                    adj[a].add(b)
                    adj[b].add(a)
        except Exception:
            pass

        calibrated = {}
        if props is not None:
            for i in range(backend.num_qubits):
                try:
                    calibrated[i] = props.readout_error(i)
                except Exception:
                    pass

        # Pick a qubit with at least two neighbours
        target = None
        for q in sorted(adj, key=lambda x: -len(adj[x])):
            if len(adj[q]) >= 2:
                target = q
                break
        if target is None:
            return None

        neighbours = sorted(adj[target])[:2]

        return {"backend": backend.name, "target": target,
                 "neighbours": neighbours, "calibrated": calibrated}
    except Exception:
        return None

def main():
    token        = os.environ.get("IBM_QUANTUM_TOKEN")
    backend_name = os.environ.get("IBM_QUANTUM_BACKEND")
    log          = open(f"module69_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "69_readout_crosstalk_leak",
        "status": "FUNCTIONAL with credentials",
        "citations": [
            ("I Know What You Are Reading: Evaluating Readout Crosstalk in "
             "Cloud-based Quantum Computers — ACM Quantum Security and Privacy "
             "Workshop 2025, DOI 10.1145/3733825.3765280"),
            ("Bell & Trügler — Reconstructing quantum circuits through "
             "side-channel information, IEEE QCE 2022, pp. 259-264"),
        ],
        "distinct_from_module66": ("module66 watches gate-error crosstalk — "
                                    "an attacker running entangling gates. "
                                    "Readout crosstalk needs no gates at all. "
                                    "A measurement-only circuit is the "
                                    "lowest-cost attack in the literature"),
        "thresholds": {
            "conditional_bias":  CORRELATION_THRESHOLD,
            "asymmetry":         ASYMMETRY_THRESHOLD,
            "calibration_gap_multiplier": CALIBRATION_GAP_MULT,
            "probe_shots":       PROBE_SHOTS,
        },
        "cost_note": ("Each probe consumes 2 circuits x "
                       f"{PROBE_SHOTS} shots of QPU time, once per "
                       f"{POLL_INTERVAL}s"),
        "credentials": "present" if token else "absent",
    })

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": ("Set IBM_QUANTUM_TOKEN to enable readout crosstalk "
                       "measurement. This module runs real circuits on the "
                       "QPU — it cannot operate offline")})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    state = load_state()

    while True:
        targets = pick_probe_targets(token, backend_name)

        if not targets:
            emit({"event": "TARGET_SELECTION_FAILED",
                  "note": "Could not resolve a probe target with 2+ neighbours"})
            time.sleep(POLL_INTERVAL)
            continue

        emit({"event":      "PROBE_START",
              "backend":    targets["backend"],
              "target":     targets["target"],
              "neighbours": targets["neighbours"]})

        probe = run_correlation_probe(token, backend_name,
                                       targets["target"],
                                       targets["neighbours"])

        if "error" in probe:
            emit({"event": "PROBE_ERROR", "detail": probe["error"]})
            time.sleep(POLL_INTERVAL)
            continue

        emit({"event":       "PROBE_COMPLETE",
              "backend":     probe["backend"],
              "job_id":      probe.get("job_id"),
              "queue_depth": probe.get("queue_depth"),
              "target":      probe["target"],
              "neighbours":  probe["neighbours"]})

        alerts = analyse_probe(probe, targets["calibrated"])
        for a in alerts:
            emit(a)

        # Record per-qubit measured error for the time-series analysis
        n_qubits = 1 + len(probe.get("neighbours", []))
        errors = {}
        for idx, nq in enumerate([probe["target"]] + probe["neighbours"]):
            e = neighbour_error_rate(probe["counts_zero"], idx,
                                      n_qubits, probe["shots"])
            if e is not None:
                errors[str(nq)] = e

        state["history"].append({"queue_depth": probe.get("queue_depth", 0),
                                  "errors":      errors,
                                  "ts":          now_iso()})

        for a in analyse_history(state):
            emit(a)

        if not alerts:
            emit({"event":   "READOUT_ISOLATION_OK",
                  "backend": probe["backend"],
                  "target":  probe["target"],
                  "measured_errors": {k: round(v, 5) for k, v in errors.items()}})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
