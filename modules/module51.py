#!/usr/bin/env python3
"""
Watchdog — Module 51: Circuit Result Verification (Refactored)
Works without qiskit on Mock provider by using dummy submission.
"""
import json, os, sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from quantum_providers import get_provider

PROBE_SHOTS = 4096

def emit(e, d):
    print(json.dumps({"event": e, "timestamp": datetime.now(timezone.utc).isoformat(), **d}))

def main():
    alerts = []
    provider = get_provider()
    emit("RUN_START", {"module": "51_result_verification", "provider": provider.provider_name})

    devices = provider.list_devices()
    device = devices[0] if devices else None
    if not device:
        emit("PROBE_SKIP", {"reason": "no device"})
        return

    # For Mock, we don't need real circuit – we can submit a dummy
    # and get_job_results will return simulated counts.
    try:
        # Check if we are on Mock – if yes, submit None
        if provider.provider_name == "MockProvider":
            circuit = None
        else:
            # Try to import qiskit for real providers
            try:
                from qiskit import QuantumCircuit
                circuit = QuantumCircuit(2)
                circuit.h(0); circuit.cx(0,1); circuit.measure_all()
            except ImportError:
                emit("PROBE_SKIP", {"reason": "qiskit not installed for real provider"})
                return

        job_id = provider.submit_circuit(circuit, shots=PROBE_SHOTS, backend=device)
        result = provider.get_job_results(job_id)
        counts = result.get("counts", {})

        total = sum(counts.values()) or 1
        p00 = counts.get("00", 0) / total
        p11 = counts.get("11", 0) / total
        forbidden = sum(counts.get(k,0) for k in counts if k not in ("00","11"))
        noise_frac = forbidden / total

        alerts = []
        if abs(p00 - 0.5) > 0.15 or abs(p11 - 0.5) > 0.15:
            alerts.append({"event": "BELL_STATE_IMBALANCE", "severity": "WARN",
                           "p00": round(p00,3), "p11": round(p11,3)})
        if noise_frac < 0.002:
            alerts.append({"event": "SUSPICIOUSLY_NOISELESS", "severity": "CRITICAL",
                           "noise_fraction": round(noise_frac,5), "note": "Too clean – likely simulation"})
        elif noise_frac > 0.15:
            alerts.append({"event": "EXCESSIVE_NOISE", "severity": "WARN",
                           "noise_fraction": round(noise_frac,4)})

        emit("PROBE_COMPLETE", {"backend": device, "job_id": job_id, "counts": counts,
                                 "alerts_triggered": len(alerts)})
        for a in alerts:
            emit(a["event"], a)
    except Exception as e:
        emit("PROBE_ERROR", {"error": str(e)})

    emit("RUN_END", {"alerts": len(alerts)})

if __name__ == "__main__":
    main()
