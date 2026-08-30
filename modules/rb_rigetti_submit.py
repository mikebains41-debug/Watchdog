#!/usr/bin/env python3
# Watchdog -- module: Randomized Benchmarking (RB) on Rigetti cepheus-1-108q
# Real hardware submission via OpenQuantum. Uses actual OpenQuantum credits.

import json, sys
from datetime import datetime, timezone
from qiskit import QuantumCircuit
from qiskit.quantum_info import Clifford, random_clifford
from qiskit import qasm2
sys.path.insert(0, "/data/data/com.termux/files/home/Watchdog")
from quantum_providers.openquantum_provider import OpenQuantumProvider

BACKEND = "rigetti:cepheus-1-108q"
SEQUENCE_LENGTHS = [2, 4, 8, 16]
SHOTS = 1024
SEED = 99

def build_rb_circuit(n_cliffords, seed):
    qc = QuantumCircuit(1, 1)
    composed = Clifford(QuantumCircuit(1))
    import numpy as np
    rng = np.random.default_rng(seed)
    for i in range(n_cliffords):
        c = random_clifford(1, seed=int(rng.integers(0, 1_000_000)))
        qc.compose(c.to_circuit(), inplace=True)
        composed = c.compose(composed)
    inverse_circuit = composed.adjoint().to_circuit()
    qc.compose(inverse_circuit, inplace=True)
    qc.measure(0, 0)
    return qc

def main():
    provider = OpenQuantumProvider()
    results = {}
    for n in SEQUENCE_LENGTHS:
        qc = build_rb_circuit(n, seed=SEED + n)
        qasm = qasm2.dumps(qc)
        job_id = provider.submit_circuit(qasm, shots=SHOTS, backend=BACKEND,
                                          name=f"Watchdog RB n={n}")
        print(json.dumps({"event": "RB_JOB_SUBMITTED", "n_cliffords": n, "job_id": job_id}))
        results[str(n)] = {"job_id": job_id, "shots": SHOTS}

    output = {
        "module": "randomized_benchmarking",
        "backend": BACKEND,
        "sequence_lengths": SEQUENCE_LENGTHS,
        "shots_per_length": SHOTS,
        "jobs": results,
        "note": "Jobs submitted, not yet retrieved -- results pending.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    with open("/data/data/com.termux/files/home/Watchdog-quantum-collab/rb_rigetti_jobs_submitted.json", "w") as f:
        json.dump(output, f, indent=2)
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
