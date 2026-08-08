#!/usr/bin/env python3
"""
Watchdog — Module 52: Transpiler Integrity (Refactored)
"""
import json, os, sys, hashlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from quantum_providers import get_provider, IBMQuantumProvider

DEPTH_RATIO_THRESHOLD   = 1.50
TWO_QUBIT_EXCESS_LIMIT  = 2
UNITARY_CHECK_MAX_QUBITS = 5
HISTORY_PATH            = os.path.expanduser("~/watchdog_transpiler_history.json")

def emit(event_type, details):
    print(json.dumps({
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **details
    }))

def load_history():
    if not os.path.exists(HISTORY_PATH):
        return {"runs": []}
    try:
        with open(HISTORY_PATH) as f:
            return json.load(f)
    except:
        return {"runs": []}

def save_history(h):
    h["runs"] = h.get("runs", [])[-50:]
    with open(HISTORY_PATH, "w") as f:
        json.dump(h, f)

def gate_census(circuit):
    try:
        return dict(circuit.count_ops())
    except:
        return {}

def two_qubit_gate_count(census):
    two_q = ["cx", "cz", "ecr", "cy", "ch", "swap", "iswap",
             "rzz", "rxx", "ryy", "cp", "crx", "cry", "crz", "cu"]
    return sum(count for gate, count in census.items() if gate in two_q)

def circuit_fingerprint(circuit):
    try:
        from qiskit import qasm3
        return hashlib.sha256(qasm3.dumps(circuit).encode()).hexdigest()
    except:
        try:
            return hashlib.sha256(str(circuit).encode()).hexdigest()
        except:
            return ""

def check_unitary_equivalence(original, transpiled):
    try:
        if original.num_qubits > UNITARY_CHECK_MAX_QUBITS:
            return {"skipped": True, "reason": f"{original.num_qubits} qubits > {UNITARY_CHECK_MAX_QUBITS}"}
        from qiskit.quantum_info import Operator
        orig_nm = original.remove_final_measurements(inplace=False)
        tran_nm = transpiled.remove_final_measurements(inplace=False)
        op_orig = Operator(orig_nm)
        op_tran = Operator(tran_nm)
        return {"skipped": False, "equivalent": bool(op_orig.equiv(op_tran))}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}

def verify_transpilation(backend):
    try:
        from qiskit import QuantumCircuit, transpile
        qc = QuantumCircuit(3)
        qc.h(0); qc.cx(0,1); qc.cx(1,2)
        qc.rz(0.7854, 2); qc.cx(0,2); qc.h(1)

        original_census = gate_census(qc)
        original_depth  = qc.depth()
        original_2q     = two_qubit_gate_count(original_census)
        original_fp     = circuit_fingerprint(qc)

        results_by_level = {}
        for level in (0, 1, 2, 3):
            try:
                t = transpile(qc, backend=backend, optimization_level=level, seed_transpiler=42)
                census = gate_census(t)
                results_by_level[level] = {
                    "depth": t.depth(),
                    "two_qubit": two_qubit_gate_count(census),
                    "census": census,
                    "n_qubits": t.num_qubits,
                }
            except Exception as e:
                results_by_level[level] = {"error": str(e)}

        ref = results_by_level.get(1, {})
        if "error" in ref:
            return {"error": f"reference transpile failed: {ref['error']}"}

        t_ref = transpile(qc, backend=backend, optimization_level=1, seed_transpiler=42)
        unitary = check_unitary_equivalence(qc, t_ref)

        return {
            "backend": backend.name,
            "backend_qubits": backend.num_qubits,
            "original": {
                "depth": original_depth,
                "two_qubit": original_2q,
                "census": original_census,
                "fingerprint": original_fp[:16],
            },
            "transpiled_by_level": results_by_level,
            "unitary_check": unitary,
            "basis_gates": list(backend.operation_names)[:12],
        }
    except Exception as e:
        return {"error": str(e)}

def analyse(result):
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

    if orig_depth > 0:
        ratio = ref_depth / orig_depth
        levels = result.get("transpiled_by_level", {})
        depths = [v.get("depth", 0) for v in levels.values()
                  if isinstance(v, dict) and "depth" in v]
        if depths and min(depths) > 0:
            spread = max(depths) / min(depths)
            if ratio > DEPTH_RATIO_THRESHOLD * 3 and spread < 1.2:
                alerts.append({
                    "event": "TRANSPILER_DEPTH_INFLATION",
                    "severity": "INFO",
                    "original_depth": orig_depth,
                    "transpiled_depth": ref_depth,
                    "ratio": round(ratio, 2),
                    "level_spread": round(spread, 2),
                    "confidence": 0.60,
                    "note": "Transpiled depth inflated across all optimization levels",
                })

    excess = ref_2q - orig_2q
    if excess > 0:
        expected_max = orig_2q * 3
        if ref_2q > expected_max + TWO_QUBIT_EXCESS_LIMIT:
            alerts.append({
                "event": "TRANSPILER_GATE_INJECTION",
                "severity": "CRITICAL",
                "original_2q": orig_2q,
                "transpiled_2q": ref_2q,
                "excess": excess,
                "routing_max": expected_max,
                "census": ref.get("census", {}),
                "confidence": 0.80,
                "note": "Extra entangling gates beyond routing – possible covert channel",
            })

    unitary = result.get("unitary_check", {})
    if not unitary.get("skipped") and unitary.get("equivalent") is False:
        alerts.append({
            "event": "TRANSPILER_UNITARY_MISMATCH",
            "severity": "CRITICAL",
            "backend": result.get("backend"),
            "confidence": 0.95,
            "note": "Transpiled circuit is NOT equivalent to the original",
        })
    elif unitary.get("skipped"):
        alerts.append({
            "event": "UNITARY_CHECK_SKIPPED",
            "severity": "INFO",
            "reason": unitary.get("reason"),
        })
    return alerts

def main():
    provider = get_provider()
    if not isinstance(provider, IBMQuantumProvider):
        emit("PROVIDER_NOT_SUPPORTED", {"provider": provider.provider_name,
                                        "note": "Module52 requires IBM Quantum"})
        return

    backend_name = os.getenv("IBM_QUANTUM_BACKEND")
    try:
        backend = provider.get_backend(backend_name)
    except Exception as e:
        emit("BACKEND_FETCH_ERROR", {"error": str(e)})
        return

    emit("RUN_START", {"module": "52_transpiler_integrity",
                       "backend": backend.name,
                       "depth_ratio_threshold": DEPTH_RATIO_THRESHOLD})

    result = verify_transpilation(backend)
    if "error" in result:
        emit("VERIFY_ERROR", {"detail": result["error"]})
    else:
        emit("TRANSPILE_VERIFIED", {
            "backend": result["backend"],
            "original_depth": result["original"]["depth"],
            "original_2q": result["original"]["two_qubit"],
            "transpiled_depth": result["transpiled_by_level"].get(1, {}).get("depth"),
            "transpiled_2q": result["transpiled_by_level"].get(1, {}).get("two_qubit"),
            "unitary_equivalent": result["unitary_check"].get("equivalent"),
            "basis_gates": result.get("basis_gates"),
        })

        alerts = analyse(result)
        for a in alerts:
            emit(a["event"], a)

        history = load_history()
        history["runs"].append({
            "backend": result["backend"],
            "depth": result["transpiled_by_level"].get(1, {}).get("depth"),
            "two_q": result["transpiled_by_level"].get(1, {}).get("two_qubit"),
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        save_history(history)

    alert_count = sum(1 for a in alerts if a.get("severity") in ("CRITICAL","WARN"))
    emit("RUN_END", {"alerts": alert_count})

if __name__ == "__main__":
    main()
