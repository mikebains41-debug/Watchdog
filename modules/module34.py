#!/usr/bin/env python3
"""
Watchdog — Module 34: QPU Calibration Drift Detector
Finds: Hardware tampering, denial of service against a QPU, or control-system
       instability, visible as anomalous recalibration behaviour.

Refactored to use quantum_providers abstraction layer.
"""
import json, os, sys, time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

# Add repo root to path for provider import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quantum_providers import get_provider, CalibrationSnapshot

# ------------------------------------------------------------------ thresholds
CALIBRATION_SPIKE_COUNT = 3
CALIBRATION_SPIKE_WINDOW = 600
T1_DROP_THRESHOLD = 0.05
T2_DROP_THRESHOLD = 0.05
POLL_INTERVAL_S = 300

# ------------------------------------------------------------------ state file
STATE_PATH = os.path.expanduser("~/watchdog_qc_calibration.json")


def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_PATH):
        return {}
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(STATE_PATH) or "/", exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, default=str)


def emit(event_type: str, device_id: str, details: Dict[str, Any]) -> None:
    print(json.dumps({
        "event": event_type,
        "device_id": device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **details
    }))


def _snapshot_to_dict(snap: CalibrationSnapshot) -> Dict[str, Any]:
    return {
        "t1_us": snap.t1_us,
        "t2_us": snap.t2_us,
        "readout_error": snap.readout_error,
        "gate_error": snap.gate_error,
        "timestamp": snap.timestamp.isoformat() if snap.timestamp else None,
    }


def check_device(provider, device_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
    device_state = state.get(device_id, {})
    baseline = device_state.get("baseline", {})
    history = device_state.get("history", [])
    now_ts = datetime.now(timezone.utc).timestamp()

    try:
        cal_data = provider.get_calibration_data(device_id)
    except Exception as e:
        emit("CALIBRATION_FETCH_FAILED", device_id, {"error": str(e)})
        return device_state

    if not cal_data:
        emit("CALIBRATION_EMPTY", device_id, {})
        return device_state

    # Establish baseline on first run
    if not baseline:
        baseline = {q: _snapshot_to_dict(s) for q, s in cal_data.items()}
        emit("BASELINE_ESTABLISHED", device_id, {"qubits": len(baseline)})
        return {"baseline": baseline, "history": [], "last_check": now_ts}

    degraded_qubits = []
    t1_drops = []
    t2_drops = []

    for qubit_id, snap in cal_data.items():
        base = baseline.get(qubit_id)
        if base is None:
            continue
        snap_dict = _snapshot_to_dict(snap)

        # T1 check
        if snap.t1_us is not None and base.get("t1_us"):
            if snap.t1_us < base["t1_us"] * (1 - T1_DROP_THRESHOLD):
                t1_drops.append({
                    "qubit": qubit_id,
                    "baseline_t1": base["t1_us"],
                    "current_t1": snap.t1_us,
                    "drop_pct": round((1 - snap.t1_us / base["t1_us"]) * 100, 2)
                })

        # T2 check
        if snap.t2_us is not None and base.get("t2_us"):
            if snap.t2_us < base["t2_us"] * (1 - T2_DROP_THRESHOLD):
                t2_drops.append({
                    "qubit": qubit_id,
                    "baseline_t2": base["t2_us"],
                    "current_t2": snap.t2_us,
                    "drop_pct": round((1 - snap.t2_us / base["t2_us"]) * 100, 2)
                })

        # Readout / gate error drift (WARN level, not CRITICAL)
        if snap.readout_error is not None and base.get("readout_error"):
            if snap.readout_error > base["readout_error"] * 2.0:
                degraded_qubits.append({
                    "qubit": qubit_id,
                    "metric": "readout_error",
                    "baseline": base["readout_error"],
                    "current": snap.readout_error,
                })

        if snap.gate_error is not None and base.get("gate_error"):
            if snap.gate_error > base["gate_error"] * 2.0:
                degraded_qubits.append({
                    "qubit": qubit_id,
                    "metric": "gate_error",
                    "baseline": base["gate_error"],
                    "current": snap.gate_error,
                })

    # Emit alerts
    if t1_drops:
        severity = "CRITICAL" if len(t1_drops) >= 3 else "WARN"
        emit("T1_COHERENCE_DEGRADATION", device_id, {
            "severity": severity,
            "affected_qubits": len(t1_drops),
            "details": t1_drops,
        })

    if t2_drops:
        severity = "CRITICAL" if len(t2_drops) >= 3 else "WARN"
        emit("T2_COHERENCE_DEGRADATION", device_id, {
            "severity": severity,
            "affected_qubits": len(t2_drops),
            "details": t2_drops,
        })

    if degraded_qubits:
        emit("CALIBRATION_FREQUENCY_SPIKE", device_id, {
            "severity": "WARN",
            "drifted_metrics": len(degraded_qubits),
            "details": degraded_qubits,
        })

    # Update history for spike detection
    history.append({"ts": now_ts, "t1_drops": len(t1_drops), "t2_drops": len(t2_drops)})
    history = [h for h in history if now_ts - h["ts"] <= CALIBRATION_SPIKE_WINDOW]
    spike_count = sum(1 for h in history if h["t1_drops"] >= 3 or h["t2_drops"] >= 3)
    if spike_count >= CALIBRATION_SPIKE_COUNT:
        emit("CALIBRATION_FREQUENCY_SPIKE", device_id, {
            "severity": "CRITICAL",
            "spike_count": spike_count,
            "window_s": CALIBRATION_SPIKE_WINDOW,
        })

    # Snapshot current cal into state
    device_state["baseline"] = {q: _snapshot_to_dict(s) for q, s in cal_data.items()}
    device_state["history"] = history
    device_state["last_check"] = now_ts

    emit("CALIBRATION_SNAPSHOT", device_id, {
        "qubits_checked": len(cal_data),
        "t1_drops": len(t1_drops),
        "t2_drops": len(t2_drops),
    })

    return device_state


def main():
    provider = get_provider()
    print(f"[module34] Using provider: {provider.provider_name}", file=sys.stderr)

    devices = provider.list_devices()
    if not devices:
        print("[module34] No devices available", file=sys.stderr)
        sys.exit(0)

    # If using mock, pick a mock device; otherwise use env or first available
    device_id = os.getenv("QUANTUM_DEVICE")
    if not device_id or device_id not in devices:
        device_id = devices[0]

    state = load_state()
    state[device_id] = check_device(provider, device_id, state)
    save_state(state)


if __name__ == "__main__":
    main()
