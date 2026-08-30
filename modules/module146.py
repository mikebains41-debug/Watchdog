#!/usr/bin/env python3
import json, numpy as np
from datetime import datetime, timezone
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector, Operator

def emit(event_type, details):
    print(json.dumps({"event": event_type, "timestamp": datetime.now(timezone.utc).isoformat(), **details}))

def test_unitarity(n_trials=20, seed=42):
    rng = np.random.default_rng(seed)
    failures = []
    for trial in range(n_trials):
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
        is_unitary = np.allclose(op.data @ op.data.conj().T, np.eye(2**n), atol=1e-8)
        if not is_unitary:
            failures.append(trial)
    return {"trials": n_trials, "failures": failures, "property_held": len(failures) == 0}

def test_probabilities_sum_to_one(n_trials=15, seed=7):
    rng = np.random.default_rng(seed)
    failures = []
    for trial in range(n_trials):
        n = int(rng.integers(1, 5))
        qc = QuantumCircuit(n)
        for _ in range(int(rng.integers(1, 6))):
            qc.h(int(rng.integers(0, n)))
        sv = Statevector(qc)
        s = sv.probabilities().sum()
        if not np.isclose(s, 1.0, atol=1e-9):
            failures.append({"trial": trial, "sum": float(s)})
    return {"trials": n_trials, "failures": failures, "property_held": len(failures) == 0}

def main():
    unitarity = test_unitarity()
    prob_sum = test_probabilities_sum_to_one()
    result = {
        "module": "module146_property_based",
        "backend": "local_simulator",
        "credits_used": 0,
        "tests": {"unitarity_property": unitarity, "probability_sum_property": prob_sum},
        "all_properties_held": unitarity["property_held"] and prob_sum["property_held"],
        "summary": "Property-based test on random circuits, checking unitarity and probability conservation. No fixed expected value used.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    emit("PROPERTY_BASED_TEST_COMPLETE", result)
    with open("module146_property_based_result.json", "w") as f:
        json.dump(result, f, indent=2)

if __name__ == "__main__":
    main()
