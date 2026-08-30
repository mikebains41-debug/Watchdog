#!/usr/bin/env python3
# Watchdog -- modules 146-150: Combined Free-Tier Test Suite
# Property-Based, Metamorphic, Mutation, Equivalence Checking, Compiler Validation
# All run locally, zero OpenQuantum credits used.

import json, numpy as np
from datetime import datetime, timezone
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector, Operator
from qiskit.qasm3 import dumps as qasm3_dumps

def now():
    return datetime.now(timezone.utc).isoformat()

# ---------- module146: Property-Based Testing ----------
def module146():
    rng = np.random.default_rng(42)
    unit_failures = []
    for trial in range(20):
        n = int(rng.integers(1, 4))
        qc = QuantumCircuit(n)
        for _ in range(int(rng.integers(1, 8))):
            gate = rng.choice(["h", "x", "cx", "ry"])
            q = int(rng.integers(0, n))
            if gate == "h": qc.h(q)
            elif gate == "x": qc.x(q)
            elif gate == "ry": qc.ry(float(rng.uniform(0, 6.28)), q)
            elif gate == "cx" and n > 1:
                q2 = int(rng.integers(0, n))
                if q2 != q: qc.cx(q, q2)
        op = Operator(qc)
        if not np.allclose(op.data @ op.data.conj().T, np.eye(2**n), atol=1e-8):
            unit_failures.append(trial)

    rng2 = np.random.default_rng(7)
    prob_failures = []
    for trial in range(15):
        n = int(rng2.integers(1, 5))
        qc = QuantumCircuit(n)
        for _ in range(int(rng2.integers(1, 6))):
            qc.h(int(rng2.integers(0, n)))
        s = Statevector(qc).probabilities().sum()
        if not np.isclose(s, 1.0, atol=1e-9):
            prob_failures.append(trial)

    return {
        "module": "module146_property_based",
        "backend": "local_simulator", "credits_used": 0,
        "tests": {
            "unitarity_property": {"trials": 20, "failures": unit_failures, "held": len(unit_failures) == 0},
            "probability_sum_property": {"trials": 15, "failures": prob_failures, "held": len(prob_failures) == 0},
        },
        "passed": len(unit_failures) == 0 and len(prob_failures) == 0,
        "timestamp": now(),
    }

# ---------- module147: Metamorphic Testing ----------
def module147():
    qc1 = QuantumCircuit(2); qc1.h(0); qc1.cx(0, 1)
    p1 = Statevector(qc1).probabilities()
    qc2 = QuantumCircuit(2); qc2.h(1); qc2.cx(1, 0)
    p2 = Statevector(qc2).probabilities()
    bell_symmetry = bool(np.allclose(p1, p2, atol=1e-9))

    qcA = QuantumCircuit(1); qcA.ry(1.234, 0)
    before = Statevector(qcA).probabilities()
    qcA.h(0); qcA.h(0)
    after = Statevector(qcA).probabilities()
    double_h_identity = bool(np.allclose(before, after, atol=1e-9))

    qcB1 = QuantumCircuit(1); qcB1.h(0)
    p_nophase = Statevector(qcB1).probabilities()
    qcB2 = QuantumCircuit(1); qcB2.h(0); qcB2.global_phase = np.pi / 3
    p_withphase = Statevector(qcB2).probabilities()
    global_phase_invariant = bool(np.allclose(p_nophase, p_withphase, atol=1e-9))

    return {
        "module": "module147_metamorphic",
        "backend": "local_simulator", "credits_used": 0,
        "tests": {
            "bell_qubit_swap_symmetry": bell_symmetry,
            "double_hadamard_identity": double_h_identity,
            "global_phase_invariance": global_phase_invariant,
        },
        "passed": bell_symmetry and double_h_identity and global_phase_invariant,
        "timestamp": now(),
    }

# ---------- module148: Mutation Testing ----------
def module148():
    def bell_prob_correct(qc):
        qc.h(0); qc.cx(0, 1)
        return Statevector(qc).probabilities()

    def bell_prob_mutated_swapped_gate(qc):
        qc.x(0); qc.cx(0, 1)
        return Statevector(qc).probabilities()

    correct = bell_prob_correct(QuantumCircuit(2))
    mutated = bell_prob_mutated_swapped_gate(QuantumCircuit(2))
    mutation_caught = not np.allclose(correct, mutated, atol=1e-9)

    return {
        "module": "module148_mutation",
        "backend": "local_simulator", "credits_used": 0,
        "description": "Deliberately mutated H-gate to X-gate in Bell circuit; checked whether the resulting statevector differs from correct version (i.e., would a real test suite catch this mutation).",
        "mutation_caught": bool(mutation_caught),
        "passed": bool(mutation_caught),
        "timestamp": now(),
    }

# ---------- module149: Equivalence Checking ----------
def module149():
    qcA = QuantumCircuit(2); qcA.h(0); qcA.cx(0, 1)
    qcB = QuantumCircuit(2); qcB.h(0); qcB.cx(0, 1); qcB.barrier()
    equivalent = bool(np.allclose(Statevector(qcA).data, Statevector(qcB).data, atol=1e-9))

    return {
        "module": "module149_equivalence_checking",
        "backend": "local_simulator", "credits_used": 0,
        "description": "Checked that adding a barrier (no-op for simulation) does not change circuit's output statevector.",
        "circuits_equivalent": equivalent,
        "passed": equivalent,
        "timestamp": now(),
    }

# ---------- module150: Compiler Validation ----------
def module150():
    qc = QuantumCircuit(2); qc.h(0); qc.cx(0, 1)
    try:
        qasm_text = qasm3_dumps(qc)
        qasm_export_ok = bool(qasm_text and 'OPENQASM' in qasm_text)
    except Exception as e:
        qasm_text = str(e)
        qasm_export_ok = False

    return {
        "module": "module150_compiler_validation",
        "backend": "local_simulator", "credits_used": 0,
        "description": "Checked that local circuit correctly exports to OpenQASM3 format (used when submitting to external vendors).",
        "qasm_export_succeeded": qasm_export_ok,
        "qasm_snippet": qasm_text[:200] if isinstance(qasm_text, str) else None,
        "passed": qasm_export_ok,
        "timestamp": now(),
    }

def main():
    results = {}
    for name, fn in [("146", module146), ("147", module147), ("148", module148), ("149", module149), ("150", module150)]:
        r = fn()
        results[name] = r
        fname = f"module{name}_result.json"
        with open(fname, "w") as f:
            json.dump(r, f, indent=2)
        print(json.dumps({"event": "MODULE_COMPLETE", "module": name, "passed": r["passed"]}))

    combined = {
        "suite": "modules_146_150_free_tier_combined",
        "total_credits_used": 0,
        "modules_run": list(results.keys()),
        "all_passed": all(r["passed"] for r in results.values()),
        "per_module_pass": {k: v["passed"] for k, v in results.items()},
        "timestamp": now(),
    }
    with open("modules_146_150_combined_result.json", "w") as f:
        json.dump(combined, f, indent=2)
    print(json.dumps(combined, indent=2))

if __name__ == "__main__":
    main()
