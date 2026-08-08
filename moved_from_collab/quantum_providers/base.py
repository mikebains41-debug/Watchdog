#!/usr/bin/env python3
"""
Watchdog — Quantum Provider Base Interface
Abstract base class for unified quantum backend access.
"""

import abc
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class CalibrationSnapshot:
    """Per-qubit calibration data from a device refresh."""
    t1_us: Optional[float] = None
    t2_us: Optional[float] = None
    readout_error: Optional[float] = None
    gate_error: Optional[float] = None
    timestamp: Optional[datetime] = None


@dataclass
class JobRecord:
    """Normalized job history entry across providers."""
    job_id: str
    device_id: str
    shots: int
    circuit_count: int
    status: str
    created_at: Optional[datetime] = None
    queue_seconds: Optional[float] = None
    exec_seconds: Optional[float] = None


@dataclass
class QueueStatus:
    """Pending workload on a specific device."""
    device_id: str
    pending_jobs: int
    status: str  # e.g. "active", "maintenance", "offline"


class QuantumProvider(abc.ABC):
    """
    Abstract interface for quantum cloud providers (IBM Quantum, D-Wave,
    Amazon Braket, etc.).  Designed to be consumed by security modules
    33-47 and calibration drift detector 34.
    """

    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name."""

    @abc.abstractmethod
    def list_devices(self) -> List[str]:
        """Return available device / backend IDs."""

    @abc.abstractmethod
    def get_calibration_data(self, device_id: str) -> Dict[str, CalibrationSnapshot]:
        """
        Return T1, T2, readout_error, gate_error per qubit (if available).
        Keys are qubit indices (str).  Used by module34.
        """

    @abc.abstractmethod
    def get_job_history(self, limit: int = 200) -> List[JobRecord]:
        """
        Return list of jobs with shots, circuit count, timing, etc.
        Used by modules 40, 42, 45.
        """

    @abc.abstractmethod
    def get_job_timing(self, job_id: str) -> Dict[str, float]:
        """
        Return queue time, execution time, etc.
        Keys: 'queue_seconds', 'exec_seconds', 'total_seconds'.
        Used by module42.
        """

    @abc.abstractmethod
    def submit_circuit(self, circuit: Any, shots: int, **kwargs) -> str:
        """
        Submit circuit and return job ID.
        `circuit` is provider-native (QuantumCircuit, BQM, etc.).
        Used by modules 33, 40, 46.
        """

    @abc.abstractmethod
    def get_queue_depth(self, device_id: str) -> QueueStatus:
        """
        Return number of pending jobs.
        Used by modules 33, 42.
        """

    def health_check(self) -> Dict[str, Any]:
        """Optional connectivity probe. Override in subclass."""
        return {"provider": self.provider_name, "status": "unknown"}

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.provider_name}>"

    def get_job_results(self, job_id: str) -> dict:
        """
        Retrieve the results (counts) for a submitted job.
        Must return a dict with at least a 'counts' key.
        """
        raise NotImplementedError
