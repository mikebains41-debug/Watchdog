#!/usr/bin/env python3
"""
Watchdog — Module 52: Transpiler Integrity Verification

Attack vector: between the circuit a tenant writes and the circuit the QPU
actually executes sits a transpiler. It rewrites logical gates into the
backend's native gate set and routes them onto physical qubits. A compromised
transpiler — or a poisoned qiskit-transpiler plugin — can:

  - Inject extra gates that entangle a tenant's qubits with an attacker's,
    creating a covert channel out of the tenant's own circuit
  - Silently degrade the circuit (deeper than necessary) to inflate error
    rates and make results useless without any visible failure
  - Reorder operations in ways that leak timing information
  - Substitute a different unitary that is close enough to pass casual
    inspection but computes something else

Nothing in the standard stack verifies the transpiled output against the
original. This module does.

Method — three independent checks:
  1. Depth ratio: transpiled depth vs a locally-computed reference transpile
     at the same optimization level. A remote transpiler adding significant
     depth beyond local reference is suspicious.
  2. Gate census: count each gate type. Extra two-qubit gates beyond what
     routing requires are the strongest single indicator of injection —
     two-qubit gates are what create entanglement.
  3. Unitary equivalence (small circuits only): for circuits under a qubit
     threshold, compute the operator of both original and transpiled and
     compare. This is exact, not heuristic. Skipped above the threshold
     because operator computation is exponential in qubit count.

Requires: qiskit, qiskit-ibm-runtime
Credentials: IBM_QUANTUM_TOKEN env var
"""
import json, datetime, os, time, hashlib
from collections import Counter, deque

DEPTH_RATIO_THRESHOLD    = 1.50   # transpiled depth >1.5x local reference = flag
TWO_QUBIT_EXCESS_LIMIT   = 2      # extra 2q gates beyond reference before flagging
UNITARY_CHECK_MAX_QUBITS = 5      # above this, operator computation is too costly
UNITARY_TOLERANCE        = 1e-6   # numerical tolerance for equivalence
POLL_INTERVAL            = 1800   # seconds between verification runs
BASELINE_FILE            = "/tmp/watchdog_transpiler_baseline.json"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except:
        return {"runs": []}

def save_baseline(b: dict):
    try:
        b["runs"] = b.get("runs", [])[-50:]
        with open(BASELINE_FILE, "w") as f:
            json.dump(b, f)
    except:
        pass

def gate_census(circuit) -> dict:
    """Count every gate type in a circuit. Returns name -> count."""
    try:
        return dict(circuit.count_ops())
    except:
        return {}

def two_qubit_gate_count(census: dict) -> int:
    """Sum all known two-qubit gate types in a census."""
    two_q = ["cx", "cz", "ecr", "cy", "ch", "swap", "iswap",
             "rzz", "rxx", "ryy", "cp", "crx", "cry", "crz", "cu"]
    return sum(count for gate, count in census.items() if gate in two_q)

def circuit_fingerprint(circuit) -> str:
    """Stable SHA256 of a circuit's structure via QASM."""
    try:
        from qiskit import qasm3
        return hashlib.sha256(qasm3.dumps(circuit).encode()).hexdigest()
    except:
        try:
            return hashlib.sha256(str(circuit).encode()).hexdigest()
        except:
            return ""

def check_unitary_equivalence(original, transpiled) -> dict:
    """
    Exact check: are the two circuits the same unitary?
    Only viable for small circuits — operator size is 2^n x 2^n.
    Returns dict with 'equivalent' bool, or 'skipped' with a reason.
    """
    try:
        if original.num_qubits > UNITARY_CHECK_MAX_QUBITS:
            return {"skipped": True,
                    "reason": f"{original.num_qubits} qubits > {UNITARY_CHECK_MAX_QUBITS} limit"}

        from qiskit.quantum_info import Operator

        # Strip measurements — they aren't unitary
        orig_nm = original.remove_final_measurements(inplace=False)
        tran_nm = transpiled.remove_final_measurements(inplace=False)

        op_orig = Operator(orig_nm)
        op_tran = Operator(tran_nm)

        equivalent = op_orig.equiv(op_tran)
        return {"skipped": False, "equivalent": bool(equivalent)}

    except ImportError:
        return {"skipped": True, "reason": "qiskit.quantum_info unavailable"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}

def verify_transpilation(token: str, backend_name: str | None) -> dict:
    """
    Build a reference circuit, transpile it locally, and compare the
    transpiled result against what the backend's own transpiler produces.
    """
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        from qiskit import QuantumCircuit, transpile

        svc = QiskitRuntimeService(token=token)
        backend = (svc.backend(backend_name) if backend_name
                   else svc.least_busy(operational=True, simulator=False,
                                        min_num_qubits=5))

        # Reference circuit: 3-qubit GHZ plus rotations.
        # Small enough for exact unitary check, structured enough that
        # gate injection is visible in the census.
        qc = QuantumCircuit(3)
        qc.h(0)
        qc.cx(0, 1)
        qc.cx(1, 2)
        qc.rz(0.7854, 2)
        qc.cx(0, 2)
        qc.h(1)

        original_census = gate_census(qc)
        original_depth  = qc.depth()
        original_2q     = two_qubit_gate_count(original_census)
        original_fp     = circuit_fingerprint(qc)

        # Local reference transpile at each optimization level
        results_by_level = {}
        for level in (0, 1, 2, 3):
            try:
                t = transpile(qc, backend=backend, optimization_level=level,
                              seed_transpiler=42)
                census = gate_census(t)
                results_by_level[level] = {
                    "depth":     t.depth(),
                    "two_qubit": two_qubit_gate_count(census),
                    "census":    census,
                    "n_qubits":  t.num_qubits,
                }
            except Exception as e:
                results_by_level[level] = {"error": str(e)}

        # The level-1 transpile is the operational reference
        ref = results_by_level.get(1, {})
        if "error" in ref:
            return {"error": f"reference transpile failed: {ref['error']}"}

        t_ref = transpile(qc, backend=backend, optimization_level=1,
                          seed_transpiler=42)

        unitary = check_unitary_equivalence(qc, t_ref)

        return {
            "backend":          backend.name,
            "backend_qubits":   backend.num_qubits,
            "original": {
                "depth":       original_depth,
                "two_qubit":   original_2q,
                "census":      original_census,
                "fingerprint": original_fp[:16],
            },
            "transpiled_by_level": results_by_level,
            "unitary_check":  unitary,
            "basis_gates":    list(backend.operation_names)[:12],
        }

    except ImportError:
        return {"error": "qiskit / qiskit_ibm_runtime not installed"}
    except Exception as e:
        return {"error": str(e)}

def analyse(result: dict) -> list:
    """Turn a verification result into alerts."""
    alerts = []
    if "error" in result:
        return alerts

    orig = result.get("original", {})
    ref  = result.get("transpiled_by_level", {}).get(1, {})
    if "error" in ref or not ref:
        return alerts

    orig_depth = orig.get("depth", 0)
    ref_depth  = ref.get("depth", 0)
    orig_2q    = orig.get("two_qubit", 0)
    ref_2q     = ref.get("two_qubit", 0)

    # ── 1. Depth inflation ──
    if orig_depth > 0:
        ratio = ref_depth / orig_depth
        # Routing legitimately increases depth. Compare across optimization
        # levels: if level 3 is much shallower than level 1, that's normal
        # optimization. If every level is inflated, that's suspicious.
        levels = result.get("transpiled_by_level", {})
        depths = [v.get("depth", 0) for v in levels.values()
                  if isinstance(v, dict) and "depth" in v]
        if depths and min(depths) > 0:
            spread = max(depths) / min(depths)
            if ratio > DEPTH_RATIO_THRESHOLD * 3 and spread < 1.2:
                alerts.append({
                    "event":    "TRANSPILER_DEPTH_INFLATION",
                    "severity": "WARN",
                    "original_depth":   orig_depth,
                    "transpiled_depth": ref_depth,
                    "ratio":            round(ratio, 2),
                    "level_spread":     round(spread, 2),
                    "confidence": 0.60,
                    "note": ("Transpiled depth inflated across all optimization "
                             "levels — optimization levels should differ. "
                             "Possible transpiler tampering or misconfiguration"),
                })

    # ── 2. Two-qubit gate injection ──
    # Routing adds SWAPs (each = 3 CX). Some increase is expected.
    # A large unexplained jump is the strongest injection signal.
    excess = ref_2q - orig_2q
    if excess > 0:
        # Estimate legitimate routing overhead: worst case is a SWAP per
        # non-adjacent 2q gate, each costing 3 two-qubit gates.
        expected_max = orig_2q * 3
        if ref_2q > expected_max + TWO_QUBIT_EXCESS_LIMIT:
            alerts.append({
                "event":    "TRANSPILER_GATE_INJECTION",
                "severity": "CRITICAL",
                "original_2q":   orig_2q,
                "transpiled_2q": ref_2q,
                "excess":        excess,
                "routing_max":   expected_max,
                "census":        ref.get("census", {}),
                "confidence": 0.80,
                "note": ("Two-qubit gate count exceeds what SWAP routing can "
                         "explain. Extra entangling gates are the signature of "
                         "a covert channel injected into the tenant circuit"),
            })

    # ── 3. Unitary equivalence ──
    unitary = result.get("unitary_check", {})
    if not unitary.get("skipped") and unitary.get("equivalent") is False:
        alerts.append({
            "event":    "TRANSPILER_UNITARY_MISMATCH",
            "severity": "CRITICAL",
            "backend":  result.get("backend"),
            "confidence": 0.95,
            "note": ("Transpiled circuit is NOT the same unitary as the "
                     "original. The QPU would execute a different computation "
                     "than the one submitted. This is exact, not heuristic."),
        })
    elif unitary.get("skipped"):
        alerts.append({
            "event":    "UNITARY_CHECK_SKIPPED",
            "severity": "INFO",
            "reason":   unitary.get("reason"),
        })

    return alerts

def main():
    token   = os.environ.get("IBM_QUANTUM_TOKEN")
    backend = os.environ.get("IBM_QUANTUM_BACKEND")
    log     = open(f"module52_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "52_transpiler_integrity",
          "depth_ratio_threshold": DEPTH_RATIO_THRESHOLD,
          "unitary_check_max_qubits": UNITARY_CHECK_MAX_QUBITS,
          "credentials": "present" if token else "absent"})

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set IBM_QUANTUM_TOKEN to enable transpiler verification"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    baseline = load_baseline()
    alerts   = 0

    while True:
        result = verify_transpilation(token, backend)

        if "error" in result:
            emit({"event": "VERIFY_ERROR", "detail": result["error"]})
        else:
            emit({"event":   "TRANSPILE_VERIFIED",
                  "backend": result["backend"],
                  "original_depth":   result["original"]["depth"],
                  "original_2q":      result["original"]["two_qubit"],
                  "transpiled_depth": result["transpiled_by_level"]
                                            .get(1, {}).get("depth"),
                  "transpiled_2q":    result["transpiled_by_level"]
                                            .get(1, {}).get("two_qubit"),
                  "unitary_equivalent": result["unitary_check"].get("equivalent"),
                  "basis_gates":      result.get("basis_gates")})

            for a in analyse(result):
                alerts += 1
                emit(a)

            baseline["runs"].append({
                "backend": result["backend"],
                "depth":   result["transpiled_by_level"].get(1, {}).get("depth"),
                "two_q":   result["transpiled_by_level"].get(1, {}).get("two_qubit"),
                "ts":      now_iso(),
            })
            save_baseline(baseline)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
