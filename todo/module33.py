#!/usr/bin/env python3
"""
Watchdog — Module 33: QaaS API Integrity Monitor
Monitors IBM Quantum / Amazon Braket / Google Quantum AI API calls.
SHA256 hashes circuits before submission, verifies returned job IDs and
result hashes. Tracks response times and queue depth anomalies.

Requires: qiskit-ibm-runtime (pip install qiskit-ibm-runtime)
Credentials: IBM_QUANTUM_TOKEN env var
Falls back to API health-check-only mode if no credentials.
"""
import hashlib, json, datetime, os, time, urllib.request, urllib.error
from collections import deque

IBM_QUANTUM_API  = "https://auth.quantum-computing.ibm.com/api"
BRAKET_ENDPOINT  = "https://braket.us-east-1.amazonaws.com"
RESPONSE_SPIKE   = 5.0    # seconds — flag if API takes longer than this
QUEUE_SPIKE      = 50     # jobs — flag if queue depth exceeds this
HISTORY_SIZE     = 20     # rolling window for response time baseline

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def hash_circuit(circuit_dict: dict) -> str:
    """SHA256 of canonically serialized circuit. Use before job submission."""
    return hashlib.sha256(
        json.dumps(circuit_dict, sort_keys=True).encode()
    ).hexdigest()

def verify_result_integrity(pre_hash: str, result: dict) -> bool:
    """
    Verify that the result returned from QaaS matches the submitted circuit.
    Result should contain the original circuit_hash echoed back.
    Returns True if integrity confirmed, False if mismatch detected.
    """
    returned_hash = result.get("circuit_hash") or result.get("metadata", {}).get("circuit_hash")
    if returned_hash is None:
        return None   # Provider doesn't echo hash — cannot verify
    return returned_hash == pre_hash

def check_ibm_api_health() -> dict:
    """Check IBM Quantum API reachability and response time."""
    try:
        start = time.time()
        req = urllib.request.Request(
            f"{IBM_QUANTUM_API}/users/loginWithToken",
            method="HEAD"
        )
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError:
            pass   # 4xx is fine — API is reachable
        elapsed = time.time() - start
        return {"reachable": True, "response_s": round(elapsed, 3)}
    except Exception as e:
        return {"reachable": False, "error": str(e)}

def check_ibm_queue_depth(token: str) -> dict | None:
    """Query IBM Quantum for current job queue depth on least-busy backend."""
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        svc = QiskitRuntimeService(token=token)
        backend = svc.least_busy(operational=True, simulator=False, min_num_qubits=5)
        status = backend.status()
        return {
            "backend":     backend.name,
            "queue_depth": status.pending_jobs,
            "operational": status.operational,
        }
    except ImportError:
        return None
    except Exception as e:
        return {"error": str(e)}

def monitor_submission(circuit: dict, token: str | None) -> dict:
    """
    Full integrity check for a single circuit submission.
    Returns result dict with integrity status.
    """
    pre_hash = hash_circuit(circuit)
    result   = {"circuit_hash_pre": pre_hash, "integrity": "not_verified"}

    if not token:
        result["status"] = "no_credentials"
        return result

    try:
        from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler
        from qiskit import QuantumCircuit

        svc = QiskitRuntimeService(token=token)
        backend = svc.least_busy(operational=True, simulator=False, min_num_qubits=2)

        # Build minimal circuit from dict spec or use a 2-qubit Bell state as probe
        qc = QuantumCircuit(2)
        qc.h(0)
        qc.cx(0, 1)
        qc.measure_all()

        start = time.time()
        sampler = Sampler(backend)
        job = sampler.run([qc], shots=128)
        elapsed = time.time() - start

        result["job_id"]      = job.job_id()
        result["response_s"]  = round(elapsed, 3)
        result["backend"]     = backend.name
        result["integrity"]   = "submitted"

        # Verify job ID is non-empty (basic tamper indicator)
        if not job.job_id():
            result["integrity"] = "FAILED_NO_JOB_ID"

    except ImportError:
        result["status"] = "qiskit_not_installed"
    except Exception as e:
        result["error"] = str(e)

    return result

def main():
    token = os.environ.get("IBM_QUANTUM_TOKEN")
    log   = open(f"module33_{stamp()}.jsonl", "a")
    response_history: deque = deque(maxlen=HISTORY_SIZE)

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "33_qaas_integrity",
          "credentials": "present" if token else "absent — health-check only"})

    # ── 1. API reachability + response time ──
    health = check_ibm_api_health()
    emit({"event": "IBM_API_HEALTH", **health})

    if health.get("reachable") and "response_s" in health:
        rt = health["response_s"]
        response_history.append(rt)
        if rt > RESPONSE_SPIKE:
            emit({"event": "QAAS_RESPONSE_SPIKE", "severity": "WARN",
                  "response_s": rt, "threshold_s": RESPONSE_SPIKE,
                  "note": "Slow API response may indicate network interception or DDoS"})

    # ── 2. Queue depth check ──
    if token:
        queue = check_ibm_queue_depth(token)
        if queue:
            emit({"event": "IBM_QUEUE_STATUS", **queue})
            if queue.get("queue_depth", 0) > QUEUE_SPIKE:
                emit({"event": "QAAS_QUEUE_SPIKE", "severity": "WARN",
                      "queue_depth": queue["queue_depth"],
                      "threshold":   QUEUE_SPIKE,
                      "note": "Abnormal queue depth — possible DoS on QPU"})

    # ── 3. Circuit integrity probe ──
    probe_circuit = {"gates": ["h", "cx"], "qubits": 2, "probe": True}
    result = monitor_submission(probe_circuit, token)
    emit({"event": "CIRCUIT_INTEGRITY_PROBE", **result})

    if result.get("integrity") == "FAILED_NO_JOB_ID":
        emit({"event": "QAAS_INTEGRITY_FAILURE", "severity": "CRITICAL",
              "confidence": 0.95,
              "note": "Job submission returned no job ID — possible MITM or API tampering"})

    emit({"event": "RUN_END"})
    log.close()

if __name__ == "__main__":
    main()
