#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_quantum_control_plane.py

Tests the six quantum control-plane security detectors: pulse-manifest
verifier, side-channel exposure auditor, crosstalk-attack detector, QTEE
verifier, reset/state-leakage checker, and fault-injection detector.

Run standalone: python3 tests/test_quantum_control_plane.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from detection.quantum_control_plane_security import (
    PulseManifestVerifier, SideChannelExposureAuditor, CrosstalkAttackDetector,
)
from detection.quantum_control_plane_security2 import (
    QTEEVerifier, ResetStateLeakageChecker, FaultInjectionDetector,
)

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


# --------------------------------------------------------------------------
# 1 -- Pulse-manifest verifier
# --------------------------------------------------------------------------
DECLARED = [{"gate": "h", "qubits": [0]}, {"gate": "cx", "qubits": [0, 1]}]


def test_manifest_match_verified():
    v = PulseManifestVerifier()
    r = v.verify(DECLARED, {"gate_ops": DECLARED, "pulse_hash": "abc"})
    check("q1: matching manifest -> QUANTUM_MANIFEST_VERIFIED",
          r["type"] == "QUANTUM_MANIFEST_VERIFIED", f"got {r['type']}")


def test_manifest_circuit_tamper():
    v = PulseManifestVerifier()
    tampered = {"gate_ops": [{"gate": "h", "qubits": [0]},
                             {"gate": "x", "qubits": [1]}], "pulse_hash": "abc"}
    r = v.verify(DECLARED, tampered)
    check("q1: gate sequence swap -> QUANTUM_CIRCUIT_TAMPER (State-Hopping)",
          r["type"] == "QUANTUM_CIRCUIT_TAMPER" and r["severity"] == "CRITICAL",
          f"got {r['type']}")


def test_manifest_pulse_tamper():
    v = PulseManifestVerifier()
    r = v.verify(DECLARED, {"gate_ops": DECLARED, "pulse_hash": "TAMPERED"},
                 expected_pulse_hash="original")
    check("q1: same gates but pulse-hash drift -> QUANTUM_PULSE_TAMPER",
          r["type"] == "QUANTUM_PULSE_TAMPER", f"got {r['type']}")


# --------------------------------------------------------------------------
# 2 -- Side-channel exposure auditor
# --------------------------------------------------------------------------
def test_sidechannel_exposed():
    a = SideChannelExposureAuditor()
    r = a.audit({"gate_ops": [{"gate": "h"}] * 5, "decoy_pulses_applied": False})
    check("q2: reconstructable + no decoy -> QUANTUM_SIDECHANNEL_EXPOSED",
          r["type"] == "QUANTUM_SIDECHANNEL_EXPOSED", f"got {r['type']}")
    check("q2: exposure result carries honest hardware note",
          "hardware_note" in r, "missing")


def test_sidechannel_protected():
    a = SideChannelExposureAuditor()
    r = a.audit({"gate_ops": [{"gate": "h"}] * 5, "decoy_pulses_applied": True})
    check("q2: reconstructable + decoy -> QUANTUM_SIDECHANNEL_PROTECTED",
          r["type"] == "QUANTUM_SIDECHANNEL_PROTECTED", f"got {r['type']}")


def test_sidechannel_low_exposure():
    a = SideChannelExposureAuditor()
    ops = [{"gate": g} for g in ["h", "cx", "rz", "sx", "ry", "cz"]]
    r = a.audit({"gate_ops": ops, "decoy_pulses_applied": False})
    check("q2: high gate variety -> LOW_EXPOSURE",
          r["type"] == "QUANTUM_SIDECHANNEL_LOW_EXPOSURE", f"got {r['type']}")


# --------------------------------------------------------------------------
# 3 -- Crosstalk-attack detector
# --------------------------------------------------------------------------
def test_crosstalk_fidelity_degradation():
    c = CrosstalkAttackDetector()
    r = c.detect(0.95, 0.80, neighbor_active=True)
    check("q3: neighbor + fidelity drop -> CROSSTALK_ATTACK_SUSPECTED",
          r["type"] == "QUANTUM_CROSSTALK_ATTACK_SUSPECTED"
          and "FIDELITY_DEGRADATION" in r["signals"], f"got {r}")


def test_crosstalk_readout_leak():
    c = CrosstalkAttackDetector()
    r = c.detect(0.95, 0.94, neighbor_active=True, readout_correlation=0.5)
    check("q3: readout correlation -> READOUT_CROSSTALK_LEAK signal",
          "READOUT_CROSSTALK_LEAK" in r.get("signals", []), f"got {r}")


def test_crosstalk_nominal_neighbor():
    c = CrosstalkAttackDetector()
    r = c.detect(0.95, 0.94, neighbor_active=True)
    check("q3: neighbor active, no degradation -> CROSSTALK_NOMINAL",
          r["type"] == "QUANTUM_CROSSTALK_NOMINAL", f"got {r['type']}")


def test_crosstalk_no_neighbor():
    c = CrosstalkAttackDetector()
    r = c.detect(0.95, 0.70, neighbor_active=False)
    check("q3: no neighbor -> QUANTUM_NO_NEIGHBOR (drop not attributed to crosstalk)",
          r["type"] == "QUANTUM_NO_NEIGHBOR", f"got {r['type']}")


# --------------------------------------------------------------------------
# 4 -- QTEE verifier
# --------------------------------------------------------------------------
def test_qtee_decoy_stripped():
    q = QTEEVerifier()
    r = q.verify({"qtee_expected": True, "decoy_pulses_declared": 8,
                  "decoy_pulses_observed": 3})
    check("q4: decoy pulses stripped -> QTEE_DECOY_STRIPPED CRITICAL",
          r["type"] == "QTEE_DECOY_STRIPPED" and r["severity"] == "CRITICAL",
          f"got {r['type']}")


def test_qtee_mask_tamper():
    q = QTEEVerifier()
    r = q.verify({"qtee_expected": True, "decoy_pulses_declared": 8,
                  "decoy_pulses_observed": 8, "pulse_mask_hash": "X",
                  "expected_pulse_mask_hash": "Y"})
    check("q4: pulse mask tamper -> QTEE_PULSE_MASK_TAMPER",
          r["type"] == "QTEE_PULSE_MASK_TAMPER", f"got {r['type']}")


def test_qtee_intact():
    q = QTEEVerifier()
    r = q.verify({"qtee_expected": True, "decoy_pulses_declared": 8,
                  "decoy_pulses_observed": 8, "pulse_mask_hash": "X",
                  "expected_pulse_mask_hash": "X"})
    check("q4: intact QTEE -> QTEE_INTACT", r["type"] == "QTEE_INTACT", f"got {r['type']}")


def test_qtee_not_requested():
    q = QTEEVerifier()
    r = q.verify({"qtee_expected": False})
    check("q4: no QTEE requested -> QTEE_NOT_REQUESTED",
          r["type"] == "QTEE_NOT_REQUESTED", f"got {r['type']}")


# --------------------------------------------------------------------------
# 5 -- Reset / state-leakage checker
# --------------------------------------------------------------------------
def test_reset_state_leak():
    r = ResetStateLeakageChecker()
    res = r.check([0.01, 0.02, 0.18, 0.01])
    check("q5: residual excited population -> QUANTUM_RESET_STATE_LEAK",
          res["type"] == "QUANTUM_RESET_STATE_LEAK" and len(res["leaky_qubits"]) == 1,
          f"got {res}")
    check("q5: leak result cites the VRAM-residual analog",
          "VRAM residual" in res["detail"], "missing analogy")


def test_reset_clean():
    r = ResetStateLeakageChecker()
    res = r.check([0.01, 0.02, 0.01, 0.00])
    check("q5: clean reset -> QUANTUM_RESET_CLEAN",
          res["type"] == "QUANTUM_RESET_CLEAN", f"got {res['type']}")


def test_reset_no_data():
    r = ResetStateLeakageChecker()
    res = r.check([])
    check("q5: no data -> RESET_CHECK_SKIPPED",
          res["type"] == "RESET_CHECK_SKIPPED", f"got {res['type']}")


# --------------------------------------------------------------------------
# 6 -- Fault-injection detector
# --------------------------------------------------------------------------
def test_fault_fidelity_floor():
    f = FaultInjectionDetector()
    r = f.detect(0.95, 0.70)
    check("q6: fidelity below physics floor -> FAULT_INJECTION_SUSPECTED",
          r["type"] == "QUANTUM_FAULT_INJECTION_SUSPECTED"
          and "FIDELITY_BELOW_PHYSICS_FLOOR" in r["signals"], f"got {r}")


def test_fault_chsh_fails_to_violate():
    f = FaultInjectionDetector()
    r = f.detect(0.95, 0.93, chsh_value=1.9, chsh_expected_violation=True)
    check("q6: CHSH fails to violate when it should -> CRITICAL fault injection",
          r["type"] == "QUANTUM_FAULT_INJECTION_SUSPECTED"
          and "CHSH_FAILS_TO_VIOLATE" in r["signals"]
          and r["severity"] == "CRITICAL", f"got {r}")


def test_fault_physics_consistent():
    f = FaultInjectionDetector()
    r = f.detect(0.95, 0.93, chsh_value=2.4, chsh_expected_violation=True)
    check("q6: physics consistent -> QUANTUM_PHYSICS_CONSISTENT",
          r["type"] == "QUANTUM_PHYSICS_CONSISTENT", f"got {r['type']}")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        try:
            t()
        except Exception as e:
            check(t.__name__, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print("\nFailures:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
