#!/usr/bin/env python3
"""
Watchdog — IBM Quantum Provider (patched for Termux)
Allows import even if qiskit is missing – only raises on circuit submit.
"""
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Try to import qiskit-ibm-runtime – required for real IBM
try:
    from qiskit_ibm_runtime import QiskitRuntimeService
    HAS_IBM_RUNTIME = True
except ImportError:
    HAS_IBM_RUNTIME = False

# qiskit is optional – only needed for circuit submission
try:
    from qiskit import QuantumCircuit
    HAS_QISKIT = True
except ImportError:
    HAS_QISKIT = False

from .base import QuantumProvider, CalibrationSnapshot, JobRecord, QueueStatus


class IBMQuantumProvider(QuantumProvider):
    def __init__(self, token: Optional[str] = None, channel: str = "ibm_quantum"):
        if not HAS_IBM_RUNTIME:
            raise RuntimeError("qiskit-ibm-runtime not installed")
        self._token = token or os.getenv("IBM_QUANTUM_TOKEN")
        self._service = QiskitRuntimeService(channel=channel, token=self._token)
        self._backends: Dict[str, Any] = {}

    @property
    def provider_name(self) -> str:
        return "IBM Quantum"

    def _get_backend(self, device_id: str):
        if device_id not in self._backends:
            self._backends[device_id] = self._service.backend(device_id)
        return self._backends[device_id]

    def get_backend(self, backend_name: Optional[str] = None):
        if backend_name is None:
            backend_name = os.getenv("IBM_QUANTUM_BACKEND")
        if backend_name:
            return self._service.backend(backend_name)
        return self._service.least_busy(operational=True, simulator=False)

    def list_devices(self) -> List[str]:
        return [b.name for b in self._service.backends()]

    def get_calibration_data(self, device_id: str) -> Dict[str, CalibrationSnapshot]:
        backend = self._get_backend(device_id)
        props = backend.properties(refresh=True)
        if props is None:
            return {}
        result: Dict[str, CalibrationSnapshot] = {}
        now = datetime.now(timezone.utc)
        for qubit_idx in range(backend.num_qubits):
            qdata = props.qubit[qubit_idx]
            t1 = t2 = readout = gate_err = None
            for item in qdata:
                name = item.get("name", "")
                if name == "T1":
                    t1 = item.get("value")
                elif name == "T2":
                    t2 = item.get("value")
                elif name == "readout_error":
                    readout = item.get("value")
            gate_errs = []
            for gate in props.gates:
                if str(qubit_idx) in [str(g) for g in gate.qubits]:
                    for param in gate.parameters:
                        if param.name == "gate_error":
                            gate_errs.append(param.value)
            gate_err = max(gate_errs) if gate_errs else None
            result[str(qubit_idx)] = CalibrationSnapshot(
                t1_us=t1,
                t2_us=t2,
                readout_error=readout,
                gate_error=gate_err,
                timestamp=now,
            )
        return result

    def get_job_history(self, limit: int = 200) -> List[JobRecord]:
        jobs = self._service.jobs(limit=limit)
        records: List[JobRecord] = []
        for job in jobs:
            metrics = getattr(job, "metrics", {}) or {}
            timing = metrics.get("timestamps", {})
            created = timing.get("created")
            if created:
                created = datetime.fromisoformat(created.replace("Z", "+00:00"))
            records.append(JobRecord(
                job_id=job.job_id,
                device_id=getattr(job, "backend_name", "unknown"),
                shots=getattr(job, "shots", 0) or 0,
                circuit_count=1,
                status=job.status().value if hasattr(job.status(), "value") else str(job.status()),
                created_at=created,
                queue_seconds=metrics.get("bss", {}).get("seconds"),
                exec_seconds=metrics.get("usage", {}).get("quantum_seconds"),
            ))
        return records

    def get_job_timing(self, job_id: str) -> Dict[str, float]:
        job = self._service.job(job_id)
        metrics = getattr(job, "metrics", {}) or {}
        bss = metrics.get("bss", {})
        usage = metrics.get("usage", {})
        return {
            "queue_seconds": bss.get("seconds", 0.0) or 0.0,
            "exec_seconds": usage.get("quantum_seconds", 0.0) or 0.0,
            "total_seconds": (bss.get("seconds", 0.0) or 0.0) + (usage.get("quantum_seconds", 0.0) or 0.0),
        }

    def submit_circuit(self, circuit: Any, shots: int, **kwargs) -> str:
        if not HAS_QISKIT:
            raise RuntimeError("qiskit not installed – cannot submit circuits")
        if not isinstance(circuit, QuantumCircuit):
            raise TypeError("IBM provider expects a qiskit.QuantumCircuit")
        backend_name = kwargs.get("backend")
        if backend_name is None:
            raise ValueError("backend name required in kwargs")
        backend = self._get_backend(backend_name)
        sampler = self._service.sampler(backend)
        job = sampler.run([circuit], shots=shots)
        return job.job_id

    def get_queue_depth(self, device_id: str) -> QueueStatus:
        backend = self._get_backend(device_id)
        status = backend.status()
        return QueueStatus(
            device_id=device_id,
            pending_jobs=status.pending_jobs,
            status="active" if status.operational else "offline",
        )

    def health_check(self) -> Dict[str, Any]:
        try:
            backends = self.list_devices()
            return {
                "provider": self.provider_name,
                "status": "ok",
                "backends_available": len(backends),
            }
        except Exception as e:
            return {
                "provider": self.provider_name,
                "status": "error",
                "error": str(e),
            }

    def get_job_results(self, job_id: str) -> dict:
        """Fetch job results – requires qiskit for counts extraction."""
        if not HAS_QISKIT:
            raise RuntimeError("qiskit not installed – cannot fetch results")
        job = self._service.job(job_id)
        result = job.result()
        try:
            pub = result[0]
            data = pub.data
            for field in dir(data):
                if field.startswith("_"):
                    continue
                obj = getattr(data, field)
                if hasattr(obj, "get_counts"):
                    counts = obj.get_counts()
                    counts = {k.replace(" ", ""): v for k, v in counts.items()}
                    return {"counts": counts}
            return {"counts": {}}
        except Exception as e:
            return {"error": str(e)}
