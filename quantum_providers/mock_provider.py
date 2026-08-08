#!/usr/bin/env python3
"""
Watchdog — Mock Quantum Provider
Dry-run provider for testing modules without cloud credentials.
"""

import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from .base import QuantumProvider, CalibrationSnapshot, JobRecord, QueueStatus


class MockQuantumProvider(QuantumProvider):
    """
    Deterministic mock for CI and local development.
    Seedable RNG for reproducible tests.
    """

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._devices = ["mock_5q", "mock_27q", "mock_127q"]

    @property
    def provider_name(self) -> str:
        return "MockProvider"

    def list_devices(self) -> List[str]:
        return list(self._devices)

    def get_calibration_data(self, device_id: str) -> Dict[str, CalibrationSnapshot]:
        num_qubits = int(device_id.split("_")[1].replace("q", ""))
        now = datetime.now(timezone.utc)
        result: Dict[str, CalibrationSnapshot] = {}
        for i in range(num_qubits):
            result[str(i)] = CalibrationSnapshot(
                t1_us=self._rng.uniform(50, 200),
                t2_us=self._rng.uniform(30, 150),
                readout_error=self._rng.uniform(0.001, 0.05),
                gate_error=self._rng.uniform(0.001, 0.02),
                timestamp=now,
            )
        return result

    def get_job_history(self, limit: int = 200) -> List[JobRecord]:
        records: List[JobRecord] = []
        for job_id, data in list(self._jobs.items())[-limit:]:
            records.append(JobRecord(
                job_id=job_id,
                device_id=data["device_id"],
                shots=data["shots"],
                circuit_count=data.get("circuit_count", 1),
                status=data.get("status", "DONE"),
                created_at=data.get("created_at"),
                queue_seconds=data.get("queue_seconds"),
                exec_seconds=data.get("exec_seconds"),
            ))
        return records

    def get_job_timing(self, job_id: str) -> Dict[str, float]:
        data = self._jobs.get(job_id, {})
        return {
            "queue_seconds": data.get("queue_seconds", 0.0),
            "exec_seconds": data.get("exec_seconds", 0.0),
            "total_seconds": data.get("queue_seconds", 0.0) + data.get("exec_seconds", 0.0),
        }

    def submit_circuit(self, circuit: Any, shots: int, **kwargs) -> str:
        job_id = f"mock-{uuid.uuid4().hex[:12]}"
        self._jobs[job_id] = {
            "device_id": kwargs.get("backend", "mock_5q"),
            "shots": shots,
            "circuit_count": 1,
            "status": "DONE",
            "created_at": datetime.now(timezone.utc),
            "queue_seconds": self._rng.uniform(0.5, 5.0),
            "exec_seconds": self._rng.uniform(0.01, 0.5),
        }
        return job_id

    def get_queue_depth(self, device_id: str) -> QueueStatus:
        return QueueStatus(
            device_id=device_id,
            pending_jobs=self._rng.randint(0, 50),
            status="active",
        )

    def health_check(self) -> Dict[str, Any]:
        return {
            "provider": self.provider_name,
            "status": "ok",
            "backends_available": len(self._devices),
        }

    def get_job_results(self, job_id: str) -> dict:
        """Return simulated counts for mock jobs."""
        import random
        # deterministic pseudo-random based on job_id
        random.seed(hash(job_id) & 0xFFFFFFFF)
        # For a Bell state (2 qubits) we can return typical counts
        # but we'll simulate random noise
        total = 4096
        # Ideal: 00 and 11 ~50% each, with small noise
        p00 = 0.5 + random.uniform(-0.02, 0.02)
        p11 = 0.5 - (p00 - 0.5)  # maintain sum 1
        counts = {
            "00": int(p00 * total),
            "11": int(p11 * total),
        }
        # add small forbidden states for realism
        remaining = total - sum(counts.values())
        counts["01"] = remaining // 2
        counts["10"] = remaining - counts["01"]
        return {"counts": counts}

    def get_job_results(self, job_id: str) -> dict:
        import random
        random.seed(hash(job_id) & 0xFFFFFFFF)
        total = 4096
        p00 = 0.5 + random.uniform(-0.02, 0.02)
        p11 = 0.5 - (p00 - 0.5)
        counts = {"00": int(p00 * total), "11": int(p11 * total)}
        remaining = total - sum(counts.values())
        counts["01"] = remaining // 2
        counts["10"] = remaining - counts["01"]
        return {"counts": counts}
