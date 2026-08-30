#!/usr/bin/env python3
# Watchdog -- module: Circuit Fingerprinting on Rigetti cepheus-1-108q
# Proves each submitted circuit actually executes fresh, not cached/replayed.
# Real hardware submission via OpenQuantum. Uses real OpenQuantum credits.

import json, sys, hashlib, random
from datetime import datetime, timezone
from qiskit import QuantumCircuit, qasm2
sys.path.insert(0, "/data/data/com.termux/files/home/Watchdog")
from quantum_providers.openquantum_provider import OpenQuantumProvider

BACKEND = "rigetti:cepheus-1-108q"
SHOTS = 512

def build_fingerprinted_circuit(marker_bits):
    n = len(marker_bits)
    qc = QuantumCircuit(n, n)
    for i, bit in enumerate(marker_bits):
        if bit == "1":
            qc.x(i)
        else:
            qc.x(i)
            qc.x(i)
    qc.measure(range(n), range(n))
    return qc

def main():
    provider = OpenQuantumProvider()

    marker = format(random.randint(0, 2**8 - 1), "08b")
    qc = build_fingerprinted_circuit(marker)
    qasm = qasm2.dumps(qc)
    qasm_hash = hashlib.sha256(qasm.encode()).hexdigest()

    job_id = provider.submit_circuit(qasm, shots=SHOTS, backend=BACKEND,
                                      name=f"Watchdog Fingerprint {marker}")

    output = {
        "module": "circuit_fingerprinting",
        "backend": BACKEND,
        "marker_bits_submitted": marker,
        "qasm_sha256": qasm_hash,
        "job_id": job_id,
        "shots": SHOTS,
        "description": (
            "A random 8-bit marker pattern was encoded into a circuit via X-gates. "
            "The submitted circuit's exact hash is recorded here. Once results are "
            "pulled, the dominant measured bitstring should match the marker exactly, "
            "proving this specific circuit executed fresh -- not a cached or replayed "
            "result from a prior run."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    with open("/data/data/com.termux/files/home/Watchdog-quantum-collab/circuit_fingerprint_submitted.json", "w") as f:
        json.dump(output, f, indent=2)
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
