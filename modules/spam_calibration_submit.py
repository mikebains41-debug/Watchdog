#!/usr/bin/env python3
# Watchdog -- module: SPAM Calibration on Rigetti cepheus-1-108q
# Measures State Preparation and Measurement error, isolated from gate error.
# Real hardware submission via OpenQuantum. Uses real OpenQuantum credits.

import json, sys
from datetime import datetime, timezone
from qiskit import QuantumCircuit, qasm2
sys.path.insert(0, "/data/data/com.termux/files/home/Watchdog")
from quantum_providers.openquantum_provider import OpenQuantumProvider

BACKEND = "rigetti:cepheus-1-108q"
SHOTS = 1024

def build_prepare_zero():
    qc = QuantumCircuit(1, 1)
    qc.x(0); qc.x(0)  # net identity, avoids idle-qubit issue
    qc.measure(0, 0)
    return qc

def build_prepare_one():
    qc = QuantumCircuit(1, 1)
    qc.x(0)
    qc.measure(0, 0)
    return qc

def main():
    provider = OpenQuantumProvider()
    jobs = {}

    for label, builder in [("prepare_0", build_prepare_zero), ("prepare_1", build_prepare_one)]:
        qc = builder()
        qasm = qasm2.dumps(qc)
        job_id = provider.submit_circuit(qasm, shots=SHOTS, backend=BACKEND,
                                          name=f"Watchdog SPAM {label}")
        jobs[label] = job_id
        print(json.dumps({"event": "SPAM_JOB_SUBMITTED", "label": label, "job_id": job_id}))

    output = {
        "module": "spam_calibration",
        "backend": BACKEND,
        "shots": SHOTS,
        "jobs": jobs,
        "description": (
            "Prepared |0> and |1> states with no computational gates applied "
            "(only net-identity or a single deterministic X), then measured. "
            "Deviation from the expected outcome isolates state-prep and "
            "measurement error from gate error."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    with open("/data/data/com.termux/files/home/Watchdog-quantum-collab/spam_calibration_submitted.json", "w") as f:
        json.dump(output, f, indent=2)
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
