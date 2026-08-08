#!/usr/bin/env python3
"""
Watchdog — D-Wave Provider
Wraps dwave-ocean-sdk for unified access.
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import dwave.cloud as dwave_cloud
    from dwave.cloud.client import Client
    HAS_DWAVE = True
except ImportError:
    HAS_DWAVE = False

from .base import QuantumProvider, CalibrationSnapshot, JobRecord, QueueStatus


class DWaveProvider(QuantumProvider):
    """
    Concrete provider for D-Wave quantum annealers.
    Requires DWAVE_API_TOKEN env var.
    """

    def __init__(self, token: Optional[str] = None, solver: Optional[str] = None):
        if not HAS_DWAVE:
            raise RuntimeError("dwave-ocean-sdk not installed")
        self._token = token or os.getenv("DWAVE_API_TOKEN")
        self._solver_name = solver or os.getenv("DWAVE_SOLVER")
        self._client = Client.from_config(token=self._token)
        self._solver = None
        if self._solver_name:
            self._solver = self._client.get_solver(name=self._solver_name)

    @property
    def provider_name(self) -> str:
        return "D-Wave"

    def list_devices(self) -> List[str]:
        return [s.id for s in self._client.get_solvers()]

    def get_calibration_data(self, device_id: str) -> Dict[str, CalibrationSnapshot]:
        solver = self._client.get_solver(name=device_id)
        props = solver.properties
        now = datetime.now(timezone.utc)
        # D-Wave doesn't expose T1/T2 like gate-based; return what we can
        qubits = props.get("qubits", [])
        result: Dict[str, CalibrationSnapshot] = {}
        for q in qubits:
            result[str(q)] = CalibrationSnapshot(
                timestamp=now,
                # Annealer-specific: no T1/T2 equivalent
            )
        return result

    def get_job_history(self, limit: int = 200) -> List[JobRecord]:
        # D-Wave client history API is limited; fetch from client
        jobs = []
        # dwave-cloud-client doesn't expose rich history like IBM;
        # return empty list as honest fallback
        return jobs

    def get_job_timing(self, job_id: str) -> Dict[str, float]:
        # D-Wave timing is embedded in problem result
        future = self._client.retrieve_answer(job_id)
        timing = future.answer.get("timing", {})
        return {
            "queue_seconds": timing.get("qpu_access_overhead_time", 0.0) / 1e6,
            "exec_seconds": timing.get("qpu_access_time", 0.0) / 1e6,
            "total_seconds": timing.get("total_real_time", 0.0) / 1e6,
        }

    def submit_circuit(self, circuit: Any, shots: int, **kwargs) -> str:
        # circuit is expected to be a dimod BQM or Ising dict
        from dimod import BinaryQuadraticModel
        if not isinstance(circuit, BinaryQuadraticModel):
            raise TypeError("D-Wave provider expects a dimod.BinaryQuadraticModel")
        solver = self._solver or self._client.get_solver()
        computation = solver.sample(circuit, num_reads=shots)
        return computation.wait_id()

    def get_queue_depth(self, device_id: str) -> QueueStatus:
        solver = self._client.get_solver(name=device_id)
        # D-Wave doesn't expose queue depth directly; return operational status
        return QueueStatus(
            device_id=device_id,
            pending_jobs=-1,  # unknown
            status="active" if solver.properties.get("status", "online") == "online" else "offline",
        )

    def health_check(self) -> Dict[str, Any]:
        try:
            solvers = self.list_devices()
            return {
                "provider": self.provider_name,
                "status": "ok",
                "solvers_available": len(solvers),
            }
        except Exception as e:
            return {
                "provider": self.provider_name,
                "status": "error",
                "error": str(e),
            }
