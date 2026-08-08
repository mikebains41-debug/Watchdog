#!/usr/bin/env python3
"""
Watchdog — Module 33: QaaS API Integrity Monitor
Refactored to use quantum_providers abstraction layer.
"""
import json, os, sys, time, hashlib
from datetime import datetime, timezone
from typing import Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from quantum_providers import get_provider

RESPONSE_SPIKE_S = 1.0
QUEUE_SPIKE_JOBS = 2


def emit(event_type: str, details: Dict[str, Any]) -> None:
    print(json.dumps({
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **details
    }))


def circuit_fingerprint(circuit) -> str:
    try:
        payload = json.dumps(circuit, sort_keys=True, default=str)
    except Exception:
        payload = str(circuit)
    return hashlib.sha256(payload.encode()).hexdigest()


def main():
    provider = get_provider()
    print(f"[module33] Using provider: {provider.provider_name}", file=sys.stderr)

    devices = provider.list_devices()
    if not devices:
        emit("API_HEALTH", {"status": "no_devices", "provider": provider.provider_name})
        return

    device_id = os.getenv("QUANTUM_DEVICE", devices[0])

    # Queue depth check
    try:
        queue = provider.get_queue_depth(device_id)
    except Exception as e:
        emit("QAAS_INTEGRITY_FAILURE", {"phase": "queue_depth", "error": str(e)})
        return

    if queue.pending_jobs > QUEUE_SPIKE_JOBS:
        emit("QAAS_QUEUE_SPIKE", {"severity": "WARN", 
            "device_id": device_id,
            "pending_jobs": queue.pending_jobs,
            "threshold": QUEUE_SPIKE_JOBS,
        })

    # Circuit integrity probe
    try:
        from qiskit import QuantumCircuit
        probe = QuantumCircuit(1, 1)
        probe.h(0)
        probe.measure(0, 0)
    except ImportError:
        probe = {"type": "probe", "ops": ["h", "measure"]}

    c_hash = circuit_fingerprint(probe)

    t0 = time.time()
    try:
        job_id = provider.submit_circuit(probe, shots=10, backend=device_id)
    except Exception as e:
        emit("QAAS_INTEGRITY_FAILURE", {"phase": "submit", "error": str(e)})
        return
    elapsed = time.time() - t0

    if elapsed > RESPONSE_SPIKE_S:
        emit("QAAS_RESPONSE_SPIKE", {
            "device_id": device_id,
            "round_trip_s": round(elapsed, 3),
            "threshold_s": RESPONSE_SPIKE_S,
        })

    emit("CIRCUIT_INTEGRITY_PROBE", {
        "device_id": device_id,
        "job_id": job_id,
        "circuit_hash": c_hash[:16],
        "round_trip_ms": round(elapsed * 1000, 2),
    })

    emit("API_HEALTH", {
        "provider": provider.provider_name,
        "device_id": device_id,
        "pending_jobs": queue.pending_jobs,
        "status": queue.status,
    })


if __name__ == "__main__":
    main()
