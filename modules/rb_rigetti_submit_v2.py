#!/usr/bin/env python3
# Watchdog -- module: Randomized Benchmarking (RB) on Rigetti cepheus-1-108q
# v2: full sequence-length range for a proper decay curve fit.
# Real hardware submission via OpenQuantum. Uses actual OpenQuantum credits.

import json, sys
from datetime import datetime, timezone
from qiskit import QuantumCircuit, qasm2
from qiskit.quantum_info import Clifford, random_clifford
sys.path.insert(0, "/data/data/com.termux/files/home/Watchdog")
from quantum_providers.openquantum_provider import OpenQuantumProvider

BACKEND = "rigetti:cepheus-1-108q"
SEQUENCE_LENGTHS = [1, 2, 4, 8, 16, 32, 64]
SHOTS = 1024
SEED = 99

def build_rb_circuit(n_cliffords, seed):
    import numpy as np
    qc = QuantumCircuit(1, 1)
    composed = Clifford(QuantumCircuit(1))
    rng = np.random.default_rng(seed)
    for i in range(n_cliffords):
        c = random_clifford(1, seed=int(rng.integers(0, 1_000_000)))
        qc.compose(c.to_circuit(), inplace=True)
        composed = composed.compose(c)
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
                                          name=f"Watchdog RB v2 n={n}")
        print(json.dumps({"event": "RB_JOB_SUBMITTED", "n_cliffords": n, "job_id": job_id}))
        results[str(n)] = {"job_id": job_id, "shots": SHOTS}

        # Save incrementally after each submission, so a Ctrl+C never loses progress
        partial_output = {
            "module": "randomized_benchmarking_v2",
            "backend": BACKEND,
            "sequence_lengths_planned": SEQUENCE_LENGTHS,
            "shots_per_length": SHOTS,
            "jobs_submitted_so_far": results,
            "note": "Incremental save -- may be partial if interrupted.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open("/data/data/com.termux/files/home/Watchdog-quantum-collab/rb_rigetti_v2_jobs_submitted.json", "w") as f:
            json.dump(partial_output, f, indent=2)

    print(json.dumps({"event": "ALL_RB_JOBS_SUBMITTED", "count": len(results)}, indent=2))

if __name__ == "__main__":
    main()
