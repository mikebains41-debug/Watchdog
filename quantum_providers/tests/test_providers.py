#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
from quantum_providers import (
    get_provider,
    MockQuantumProvider,
    QuantumProvider,
    CalibrationSnapshot,
    JobRecord,
    QueueStatus,
)


def test_get_provider_returns_mock_without_credentials(monkeypatch):
    monkeypatch.delenv("IBM_QUANTUM_TOKEN", raising=False)
    monkeypatch.delenv("DWAVE_API_TOKEN", raising=False)
    p = get_provider()
    assert p.provider_name == "MockProvider"


def test_mock_provider_list_devices():
    p = MockQuantumProvider()
    devs = p.list_devices()
    assert "mock_5q" in devs
    assert "mock_127q" in devs


def test_mock_calibration_data():
    p = MockQuantumProvider()
    cal = p.get_calibration_data("mock_5q")
    assert len(cal) == 5
    assert "0" in cal
    assert cal["0"].t1_us is not None
    assert cal["0"].t2_us is not None


def test_mock_submit_and_history():
    p = MockQuantumProvider()
    job_id = p.submit_circuit({"test": "circuit"}, shots=100, backend="mock_5q")
    assert job_id.startswith("mock-")
    jobs = p.get_job_history()
    assert len(jobs) == 1
    assert jobs[0].shots == 100
    assert jobs[0].job_id == job_id


def test_mock_queue_depth():
    p = MockQuantumProvider()
    q = p.get_queue_depth("mock_5q")
    assert q.status == "active"
    assert q.pending_jobs >= 0


def test_mock_job_timing():
    p = MockQuantumProvider()
    job_id = p.submit_circuit(None, shots=1)
    timing = p.get_job_timing(job_id)
    assert "exec_seconds" in timing
    assert timing["exec_seconds"] >= 0
    assert "queue_seconds" in timing


def test_base_is_abstract():
    with pytest.raises(TypeError):
        QuantumProvider()
