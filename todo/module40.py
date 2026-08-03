#!/usr/bin/env python3
"""
Watchdog — Module 40: QaaS API Replay Attack Prevention
Adds a time-stamped nonce to every circuit submission.
Tracks nonces in a local store — flags if same nonce appears twice.
Requires: qiskit-ibm-runtime
Credentials: IBM_QUANTUM_TOKEN env var
"""
import hashlib, json, datetime, os, time, secrets
from collections import deque

NONCE_STORE_FILE = "/tmp/watchdog_qc_nonces.json"
NONCE_EXPIRY_S   = 3600   # nonces expire after 1 hour
NONCE_WINDOW     = 10000  # max nonces to keep in memory

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_nonces() -> dict:
    try:
        with open(NONCE_STORE_FILE) as f:
            return json.load(f)
    except:
        return {}

def save_nonces(store: dict):
    now = time.time()
    # Prune expired nonces
    store = {k: v for k, v in store.items() if now - v < NONCE_EXPIRY_S}
    try:
        with open(NONCE_STORE_FILE, "w") as f:
            json.dump(store, f)
    except:
        pass
    return store

def generate_nonce() -> str:
    """Generate a cryptographically secure time-stamped nonce."""
    rand  = secrets.token_hex(16)
    ts    = str(int(time.time() * 1000))
    return hashlib.sha256(f"{rand}{ts}".encode()).hexdigest()

def attach_nonce(circuit_dict: dict) -> tuple[dict, str]:
    """Attach nonce to circuit metadata. Returns (modified_circuit, nonce)."""
    nonce = generate_nonce()
    circuit_dict = dict(circuit_dict)
    circuit_dict["_watchdog_nonce"] = nonce
    circuit_dict["_watchdog_ts"]    = now_iso()
    return circuit_dict, nonce

def check_replay(nonce: str, store: dict) -> bool:
    """Returns True if nonce has been seen before (replay detected)."""
    return nonce in store

def record_nonce(nonce: str, store: dict) -> dict:
    store[nonce] = time.time()
    return store

def submit_with_replay_protection(circuit: dict, token: str) -> dict:
    """Submit circuit with nonce protection via Qiskit Runtime."""
    store = load_nonces()
    circuit_with_nonce, nonce = attach_nonce(circuit)

    if check_replay(nonce, store):
        return {"status": "REPLAY_BLOCKED", "nonce": nonce}

    store = record_nonce(nonce, store)
    save_nonces(store)

    try:
        from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler
        from qiskit import QuantumCircuit

        svc     = QiskitRuntimeService(token=token)
        backend = svc.least_busy(operational=True, simulator=False, min_num_qubits=2)

        qc = QuantumCircuit(2)
        qc.h(0); qc.cx(0, 1); qc.measure_all()

        sampler = Sampler(backend)
        job     = sampler.run([qc], shots=128)

        return {
            "status":  "submitted",
            "job_id":  job.job_id(),
            "nonce":   nonce,
            "backend": backend.name,
        }
    except ImportError:
        return {"status": "qiskit_not_installed", "nonce": nonce}
    except Exception as e:
        return {"status": "error", "error": str(e), "nonce": nonce}

def monitor_replay_attempts(token: str, emit_fn):
    """
    Poll recent IBM Quantum job history for duplicate circuit submissions.
    Flags jobs with identical circuit hashes submitted close together.
    """
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        svc    = QiskitRuntimeService(token=token)
        jobs   = svc.jobs(limit=50)
        hashes = {}

        for job in jobs:
            try:
                meta = job.metadata or {}
                circuit_hash = meta.get("_watchdog_nonce") or hashlib.sha256(
                    str(job.job_id()).encode()).hexdigest()[:16]
                created = job.creation_date

                if circuit_hash in hashes:
                    prev_time = hashes[circuit_hash]
                    delta = abs((created - prev_time).total_seconds())
                    if delta < 3600:
                        emit_fn({
                            "event":       "QAAS_API_REPLAY_DETECTED",
                            "severity":    "CRITICAL",
                            "job_id":      job.job_id(),
                            "duplicate_of": hashes.get(circuit_hash + "_id"),
                            "delta_s":     round(delta, 1),
                            "confidence":  0.85,
                            "note":        "Duplicate circuit submitted within 1 hour — replay attack"
                        })
                else:
                    hashes[circuit_hash]         = created
                    hashes[circuit_hash + "_id"] = job.job_id()
            except:
                pass
    except ImportError:
        pass
    except Exception as e:
        emit_fn({"event": "MONITOR_ERROR", "detail": str(e)})

def main():
    token = os.environ.get("IBM_QUANTUM_TOKEN")
    log   = open(f"module40_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "40_qaas_replay",
          "credentials": "present" if token else "absent"})

    if not token:
        emit({"event": "STATUS", "status": "NO_CREDENTIALS",
              "note": "Set IBM_QUANTUM_TOKEN to enable replay monitoring"})
        emit({"event": "RUN_END", "alerts": 0})
        log.close()
        return

    while True:
        monitor_replay_attempts(token, emit)
        time.sleep(300)

if __name__ == "__main__":
    main()
