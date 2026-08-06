#!/usr/bin/env python3
"""
Watchdog — Module 67: Dynamical Decoupling Enforcement
Status: FUNCTIONAL — verification works offline, live check with credentials

PUBLISHED DEFENCE THIS MODULE ENFORCES:

  Mehra, D. & Kalev, A. "Towards defending crosstalk-mediated attacks in
  multi-tenant quantum computing." Physica Scripta 101, 095102 (2026).
  DOI 10.1088/1402-4896/ae4429.
  Tested on the 127-qubit ibm_brisbane QPU. The paper examines
  crosstalk-mediated attacks against a three-qubit Grover's search and
  evaluates two mitigations — gate-based dynamical decoupling and buffer
  qubits — finding that while both offer some mitigation individually,
  their COMBINED application yields the most significant improvement.

  Pokharel, B., Anand, N., Fortman, B. & Lidar, D.A. "Demonstration of
  fidelity improvement using dynamical decoupling with superconducting
  qubits." Phys. Rev. Lett. 121, 220502 (2018).

  Tripathi, V. et al. "Suppression of crosstalk in superconducting qubits
  using dynamical decoupling." (2022). Establishes DD applied to spectator
  qubits; Mehra & Kalev extend it to computation qubits.

WHAT DYNAMICAL DECOUPLING IS: a sequence of pulses inserted into the idle
periods of a circuit that echoes away low-frequency noise — including the
noise a co-tenant's crosstalk injects. An idle qubit with no DD is fully
exposed for the whole duration it sits idle. An idle qubit with an XY4 or
XY8 sequence has that exposure largely cancelled.

THE GAP THIS CLOSES: DD is not applied by default. Qiskit provides
PadDynamicalDecoupling as an optional transpiler pass. A tenant who does
not explicitly enable it submits circuits with every idle window
unprotected — and has no indication anything is missing.

WHAT THIS MODULE DOES:
  - Analyses a transpiled circuit for idle windows on each qubit
  - Detects whether DD sequences are present, and which family
    (XY4, XY8, CPMG, CP, or a bare X-X pair)
  - Computes the fraction of total idle time that is protected
  - Flags idle windows above a duration threshold with no DD
  - Verifies the DD sequence itself is well-formed — an incorrectly
    constructed sequence provides no protection while looking like it does
  - Where credentials are present, checks the live backend supports the
    gates the DD sequence requires

Requires: qiskit (offline analysis), qiskit-ibm-runtime (live check)
Credentials: IBM_QUANTUM_TOKEN — optional
"""
import json, os, time, datetime
from collections import defaultdict, Counter

POLL_INTERVAL        = 1800
IDLE_THRESHOLD_NS    = 500      # idle window above this should carry DD
DD_COVERAGE_FLOOR    = 0.60     # <60% of idle time protected = alert
MIN_DD_PULSES        = 2        # a DD sequence needs at least 2 pulses
STATE_FILE           = "/tmp/watchdog_dd_enforcement.json"

# Recognised DD sequence signatures, by the gate pattern they produce
DD_FAMILIES = {
    "XY4":  ["x", "y", "x", "y"],
    "XY8":  ["x", "y", "x", "y", "y", "x", "y", "x"],
    "CPMG": ["y", "y"],
    "CP":   ["x", "x"],
    "XX":   ["x", "x"],
}

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"assessments": []}

def save_state(s: dict):
    try:
        s["assessments"] = s.get("assessments", [])[-100:]
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def identify_dd_family(gate_sequence: list) -> str | None:
    """
    Given the ordered single-qubit gates found in one idle window,
    identify which DD family it matches. Returns None if it matches none.
    """
    if len(gate_sequence) < MIN_DD_PULSES:
        return None
    normalised = [g.lower() for g in gate_sequence]

    for family, pattern in DD_FAMILIES.items():
        if normalised == pattern:
            return family
        # Repeated application of the base sequence
        if len(normalised) % len(pattern) == 0 and len(normalised) > 0:
            reps = len(normalised) // len(pattern)
            if normalised == pattern * reps:
                return f"{family}x{reps}"

    # A bare pair of identical pulses is a minimal echo — weak but present
    if len(normalised) == 2 and normalised[0] == normalised[1]:
        return f"echo_{normalised[0]}"

    return None

def analyse_circuit_dd(circuit) -> dict:
    """
    Walk a scheduled circuit and measure DD coverage per qubit.

    Requires a circuit that has been through a scheduling pass so that
    Delay instructions are present. Without scheduling there are no
    explicit idle windows to measure.
    """
    try:
        from qiskit.circuit import Delay
    except ImportError:
        return {"error": "qiskit not available"}

    n = circuit.num_qubits
    per_qubit = {q: {"delays": [], "total_delay": 0, "protected_delay": 0,
                      "unprotected_windows": [], "dd_families": []}
                 for q in range(n)}

    # Track, per qubit, the gates that fall between delay instructions
    pending = defaultdict(list)
    has_delays = False

    try:
        for inst in circuit.data:
            op   = inst.operation
            qbits = [circuit.find_bit(q).index for q in inst.qubits]

            if isinstance(op, Delay) or op.name == "delay":
                has_delays = True
                duration = getattr(op, "duration", 0) or 0
                for q in qbits:
                    fam = identify_dd_family(pending[q])
                    per_qubit[q]["delays"].append({
                        "duration":  duration,
                        "dd_family": fam,
                        "pulses":    list(pending[q]),
                    })
                    per_qubit[q]["total_delay"] += duration
                    if fam:
                        per_qubit[q]["protected_delay"] += duration
                        per_qubit[q]["dd_families"].append(fam)
                    elif duration > IDLE_THRESHOLD_NS:
                        per_qubit[q]["unprotected_windows"].append(duration)
                    pending[q] = []
            elif len(qbits) == 1:
                # Single-qubit gate — candidate DD pulse
                pending[qbits[0]].append(op.name)
            else:
                # Two-qubit gate ends any DD accumulation on both qubits
                for q in qbits:
                    pending[q] = []
    except Exception as e:
        return {"error": f"circuit walk failed: {e}"}

    total_delay     = sum(v["total_delay"] for v in per_qubit.values())
    protected_delay = sum(v["protected_delay"] for v in per_qubit.values())
    coverage = (protected_delay / total_delay) if total_delay > 0 else None

    all_families = []
    for v in per_qubit.values():
        all_families.extend(v["dd_families"])

    unprotected = []
    for q, v in per_qubit.items():
        for d in v["unprotected_windows"]:
            unprotected.append({"qubit": q, "duration_ns": d})

    return {
        "has_scheduling":     has_delays,
        "num_qubits":         n,
        "total_delay_ns":     total_delay,
        "protected_delay_ns": protected_delay,
        "dd_coverage":        round(coverage, 4) if coverage is not None else None,
        "dd_families_found":  dict(Counter(all_families)),
        "unprotected_windows": sorted(unprotected,
                                       key=lambda x: -x["duration_ns"])[:20],
        "unprotected_count":  len(unprotected),
        "per_qubit":          {str(q): {"total_delay": v["total_delay"],
                                         "protected":   v["protected_delay"],
                                         "unprotected": len(v["unprotected_windows"])}
                                for q, v in per_qubit.items()},
    }

def build_and_schedule_reference(token: str | None,
                                  backend_name: str | None,
                                  apply_dd: bool) -> dict:
    """
    Build a reference circuit with an idle window, transpile and schedule it,
    optionally applying PadDynamicalDecoupling. Comparing the with-DD and
    without-DD results is what proves the check works.
    """
    try:
        from qiskit import QuantumCircuit, transpile
        from qiskit.transpiler import PassManager
        from qiskit.circuit.library import XGate

        if token:
            from qiskit_ibm_runtime import QiskitRuntimeService
            svc = QiskitRuntimeService(token=token)
            backend = (svc.backend(backend_name) if backend_name
                       else svc.least_busy(operational=True, simulator=False,
                                            min_num_qubits=5))
        else:
            return {"error": "no credentials — cannot schedule without a backend"}

        # Circuit with a deliberate idle period on qubit 1
        qc = QuantumCircuit(3)
        qc.h(0)
        qc.cx(0, 2)          # qubit 1 idles through this
        qc.cx(0, 2)
        qc.measure_all()

        t = transpile(qc, backend=backend, optimization_level=1,
                      scheduling_method="alap", seed_transpiler=42)

        if apply_dd:
            try:
                from qiskit.transpiler.passes import (
                    ALAPScheduleAnalysis, PadDynamicalDecoupling)
                durations = backend.instruction_durations
                dd_sequence = [XGate(), XGate()]
                pm = PassManager([
                    ALAPScheduleAnalysis(durations),
                    PadDynamicalDecoupling(durations, dd_sequence),
                ])
                t = pm.run(t)
            except Exception as e:
                return {"error": f"DD pass failed: {e}", "backend": backend.name}

        return {"circuit": t, "backend": backend.name,
                 "dd_applied": apply_dd}
    except ImportError:
        return {"error": "qiskit / qiskit_ibm_runtime not installed"}
    except Exception as e:
        return {"error": str(e)}

def check_backend_dd_support(token: str, backend_name: str | None) -> dict:
    """
    Does the backend's basis gate set support the pulses a DD sequence needs?
    An XY4 sequence needs both X and Y; many backends only expose X and RZ,
    requiring Y to be synthesised, which changes the timing.
    """
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        svc = QiskitRuntimeService(token=token)
        backend = (svc.backend(backend_name) if backend_name
                   else svc.least_busy(operational=True, simulator=False,
                                        min_num_qubits=5))
        basis = list(backend.operation_names)
        return {
            "backend":    backend.name,
            "basis_gates": basis,
            "has_x":      "x" in basis,
            "has_y":      "y" in basis,
            "has_rz":     "rz" in basis,
            "has_sx":     "sx" in basis,
            "xy4_native": "x" in basis and "y" in basis,
            "note": ("XY4 requires native X and Y. Without native Y, the "
                     "sequence is synthesised from RZ/SX which alters pulse "
                     "timing and can weaken the echo"),
        }
    except Exception as e:
        return {"error": str(e)}

def analyse(result: dict, backend_support: dict) -> list:
    alerts = []

    if "error" in result:
        return alerts

    # ── 1. No scheduling means no measurable idle windows ──
    if not result.get("has_scheduling"):
        alerts.append({
            "event":    "CIRCUIT_NOT_SCHEDULED",
            "severity": "WARN",
            "confidence": 0.60,
            "note": ("The circuit carries no Delay instructions, so idle "
                     "windows cannot be measured. Transpile with "
                     "scheduling_method='alap' to expose them. Without "
                     "scheduling, DD cannot be applied or verified"),
        })
        return alerts

    coverage = result.get("dd_coverage")
    total    = result.get("total_delay_ns", 0)

    # ── 2. No DD at all ──
    if total > 0 and (coverage is None or coverage == 0):
        alerts.append({
            "event":    "NO_DYNAMICAL_DECOUPLING",
            "severity": "CRITICAL",
            "total_idle_ns":   total,
            "unprotected_windows": result.get("unprotected_count"),
            "confidence": 0.85,
            "citation": "Phys. Scr. 101, 095102 (2026), DOI 10.1088/1402-4896/ae4429",
            "note": (f"{total} ns of total qubit idle time with zero dynamical "
                     "decoupling applied. Every idle window is fully exposed to "
                     "crosstalk from a co-tenant for its entire duration. The "
                     "published defence is DD combined with buffer qubits"),
            "remediation": ("Add PadDynamicalDecoupling to the transpiler "
                            "PassManager with an XGate/XGate or XY4 sequence"),
        })

    # ── 3. Partial coverage ──
    elif coverage is not None and coverage < DD_COVERAGE_FLOOR:
        alerts.append({
            "event":    "INSUFFICIENT_DD_COVERAGE",
            "severity": "WARN",
            "coverage": coverage,
            "floor":    DD_COVERAGE_FLOOR,
            "protected_ns":   result.get("protected_delay_ns"),
            "total_idle_ns":  total,
            "unprotected_count": result.get("unprotected_count"),
            "confidence": 0.70,
            "citation": "Phys. Scr. 101, 095102 (2026)",
            "note": (f"Only {coverage*100:.1f}% of idle time carries a DD "
                     "sequence. The remainder is unprotected exposure window"),
        })

    # ── 4. Long unprotected windows ──
    unprotected = result.get("unprotected_windows", [])
    if unprotected:
        worst = unprotected[0]
        alerts.append({
            "event":    "LONG_UNPROTECTED_IDLE",
            "severity": "WARN",
            "worst_window_ns": worst["duration_ns"],
            "worst_qubit":     worst["qubit"],
            "threshold_ns":    IDLE_THRESHOLD_NS,
            "count":           len(unprotected),
            "windows":         unprotected[:8],
            "confidence": 0.65,
            "note": (f"Qubit {worst['qubit']} idles for {worst['duration_ns']} ns "
                     "with no decoupling pulses. Longer idle means more "
                     "accumulated crosstalk phase error"),
        })

    # ── 5. Weak DD family ──
    families = result.get("dd_families_found", {})
    weak = {f: c for f, c in families.items()
            if f.startswith("echo_") or f in ("CP", "XX")}
    if weak and coverage:
        alerts.append({
            "event":    "WEAK_DD_SEQUENCE",
            "severity": "INFO",
            "families": families,
            "weak":     weak,
            "confidence": 0.50,
            "citation": "Pokharel et al., Phys. Rev. Lett. 121, 220502 (2018)",
            "note": ("A bare two-pulse echo is present rather than XY4 or XY8. "
                     "Two-pulse sequences cancel dephasing along one axis only; "
                     "XY4 cancels along both and is the standard choice for "
                     "crosstalk suppression"),
        })

    # ── 6. Backend cannot support XY4 natively ──
    if backend_support and not backend_support.get("error"):
        if not backend_support.get("xy4_native"):
            alerts.append({
                "event":    "XY4_NOT_NATIVE",
                "severity": "INFO",
                "backend":  backend_support.get("backend"),
                "basis_gates": backend_support.get("basis_gates", [])[:10],
                "confidence": 0.45,
                "note": backend_support.get("note"),
            })

    return alerts

def main():
    token   = os.environ.get("IBM_QUANTUM_TOKEN")
    backend = os.environ.get("IBM_QUANTUM_BACKEND")
    log     = open(f"module67_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "67_dd_enforcement",
        "status": "FUNCTIONAL — live scheduling requires credentials",
        "enforces": [
            "Mehra & Kalev, Phys. Scr. 101, 095102 (2026) — DD + buffer qubits, "
            "tested on 127-qubit ibm_brisbane",
            "Pokharel et al., Phys. Rev. Lett. 121, 220502 (2018) — DD fidelity improvement",
            "Tripathi et al. (2022) — DD crosstalk suppression",
        ],
        "checks": [
            "Idle window detection via scheduled Delay instructions",
            "DD sequence family identification (XY4, XY8, CPMG, CP, echo)",
            "Fraction of total idle time carrying DD protection",
            "Idle windows above threshold with no DD",
            "DD sequence well-formedness",
            "Backend native gate support for XY4",
        ],
        "idle_threshold_ns": IDLE_THRESHOLD_NS,
        "coverage_floor":    DD_COVERAGE_FLOOR,
        "credentials": "present" if token else "absent",
    })

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": ("Set IBM_QUANTUM_TOKEN to schedule circuits against a "
                       "real backend. The DD analysis functions can be called "
                       "directly on any scheduled circuit without credentials.")})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    state  = load_state()
    alerts = 0

    while True:
        support = check_backend_dd_support(token, backend)
        if "error" not in support:
            emit({"event": "BACKEND_DD_SUPPORT", **support})

        # Assess a circuit WITHOUT DD — this is the default a tenant gets
        no_dd = build_and_schedule_reference(token, backend, apply_dd=False)
        if "error" in no_dd:
            emit({"event": "SCHEDULE_ERROR", "phase": "no_dd",
                  "detail": no_dd["error"]})
        else:
            result = analyse_circuit_dd(no_dd["circuit"])
            emit({"event":   "DD_ASSESSMENT",
                  "dd_applied": False,
                  "backend": no_dd["backend"],
                  **{k: v for k, v in result.items() if k != "per_qubit"}})

            for a in analyse(result, support):
                alerts += 1
                emit(a)

            state["assessments"].append({
                "dd_applied": False,
                "coverage":   result.get("dd_coverage"),
                "ts":         now_iso(),
            })

        # Assess the same circuit WITH DD — proves the detection works
        with_dd = build_and_schedule_reference(token, backend, apply_dd=True)
        if "error" in with_dd:
            emit({"event": "DD_PASS_UNAVAILABLE",
                  "detail": with_dd["error"],
                  "note": ("PadDynamicalDecoupling could not be applied on this "
                           "Qiskit version or backend. The defence published in "
                           "Phys. Scr. 101, 095102 cannot be enabled here")})
        else:
            result = analyse_circuit_dd(with_dd["circuit"])
            emit({"event":   "DD_ASSESSMENT",
                  "dd_applied": True,
                  "backend": with_dd["backend"],
                  **{k: v for k, v in result.items() if k != "per_qubit"}})

            cov = result.get("dd_coverage")
            if cov is not None and cov > 0:
                emit({"event": "DD_VERIFIED_WORKING",
                      "coverage": cov,
                      "families": result.get("dd_families_found"),
                      "note": ("DD pass applied and detected. Enable this in "
                               "the production transpiler PassManager")})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
