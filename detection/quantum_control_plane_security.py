#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
quantum_control_plane_security.py -- Quantum Control-Plane Security (Part 1)
Part of Watchdog Quantum Security & Physics Suite.

Quantum processors are driven by classical control planes (transpilers,
FPGA pulse generators, cryo controllers, job APIs). That classical-to-
quantum interface is the frontier attack surface -- and it is almost
entirely UNoccupied commercially. The competition does PQC/QKD (protecting
classical data from future quantum computers); nobody monitors the QPU's
own control plane or uses the hardware's physics as a tamper-verifier.

This module implements three control-plane security detectors, each
grounded in published research:

1. PulseManifestVerifier -- verify the transpiled pulse sequence matches
   the declared high-level gate manifest. Detects "State-Hopping" / circuit
   tampering between submission and execution -- the exact "real-time
   verification of pulse-level instructions against high-level gate
   manifests" problem named as open by Google's Quantum Computing Security
   program. Extends Watchdog's existing circuit-fingerprinting to the
   pulse level.

2. SideChannelExposureAuditor -- audit whether a circuit is reconstructable
   via the controller's power / 4-8 GHz EM emissions, and whether decoy-
   pulse protection is applied. Based on Xu/Erata/Szefer, "Exploration of
   Power Side-Channel Vulnerabilities in Quantum Computer Controllers"
   (ACM CCS 2023) and Bell/Trugler circuit-reconstruction (IEEE QCE 2022).
   (EM measurement itself is hardware-gated -- needs an SDR -- so this is an
   exposure/structure audit, honestly labeled.)

3. CrosstalkAttackDetector -- detect a co-tenant degrading or inferring a
   victim circuit via crosstalk on a shared multi-tenant QPU. Based on the
   SWAP attack (arXiv:2502.10115), crosstalk attacks & defence (arXiv:
   2402.02753), and readout crosstalk end-to-end attack (ACM QSP 2025).

Pure logic over job metadata / result statistics. No live QPU call inside
the module -- the caller wires in real job data. Fully testable.

NOTE: Simulation-based. Requires real hardware validation. Thresholds are
grounded in the cited research; per-backend calibration required.
"""

import hashlib
import statistics
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# 1 -- Pulse-manifest integrity verifier
# ---------------------------------------------------------------------------
class PulseManifestVerifier:
    """
    Verify the transpiled pulse program matches the declared gate manifest.

    declared_manifest: the high-level gate list the USER submitted, e.g.
        [{"gate": "h", "qubits": [0]}, {"gate": "cx", "qubits": [0, 1]}, ...]
    transpiled_pulses: the pulse-level program that will actually execute,
        summarized as {"gate_ops": [...], "pulse_hash": "..."} where gate_ops
        is the sequence of logical ops the pulses implement (recovered from
        the transpilation) and pulse_hash is a fingerprint of the raw pulses.
    expected_pulse_hash: (optional) a sealed pulse fingerprint from a trusted
        transpilation, to catch pulse-level tampering that preserves the
        logical gate sequence.
    """

    def _manifest_fingerprint(self, ops: list) -> str:
        canon = ";".join(f"{o.get('gate')}:{','.join(map(str, o.get('qubits', [])))}"
                         for o in ops)
        return hashlib.sha256(canon.encode()).hexdigest()

    def verify(self, declared_manifest: list, transpiled_pulses: dict,
               expected_pulse_hash: str = None) -> dict:
        declared_fp = self._manifest_fingerprint(declared_manifest)
        executed_ops = transpiled_pulses.get("gate_ops", [])
        executed_fp = self._manifest_fingerprint(executed_ops)
        pulse_hash = transpiled_pulses.get("pulse_hash")

        result = {
            "substrate": "quantum",
            "declared_gate_count": len(declared_manifest),
            "executed_gate_count": len(executed_ops),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "PulseManifestVerifier",
        }

        # 1. Logical gate sequence must match (State-Hopping / circuit swap)
        if declared_fp != executed_fp:
            result["type"] = "QUANTUM_CIRCUIT_TAMPER"
            result["severity"] = "CRITICAL"
            result["detail"] = ("transpiled pulse program implements a "
                                "DIFFERENT gate sequence than the declared "
                                "manifest (State-Hopping / circuit swap)")
            result["cite"] = "Google QC Security program; pulse-vs-manifest verification"
            result["recommended_action"] = {"action": "reject_job_and_escalate",
                                            "risk": "gated"}
            return result

        # 2. Pulse-level tamper that preserves logical gates (decoy strip,
        #    pulse-parameter manipulation) -- caught only by the raw pulse hash
        if expected_pulse_hash is not None and pulse_hash != expected_pulse_hash:
            result["type"] = "QUANTUM_PULSE_TAMPER"
            result["severity"] = "CRITICAL"
            result["detail"] = ("logical gates match but raw pulse fingerprint "
                                "differs from the sealed value -- pulse-level "
                                "manipulation (parameter tamper / decoy strip)")
            result["recommended_action"] = {"action": "reject_job_and_escalate",
                                            "risk": "gated"}
            return result

        result["type"] = "QUANTUM_MANIFEST_VERIFIED"
        result["severity"] = "INFO"
        return result


# ---------------------------------------------------------------------------
# 2 -- Side-channel exposure auditor
# ---------------------------------------------------------------------------
class SideChannelExposureAuditor:
    """
    Audit whether a circuit is exposed to power/EM side-channel
    reconstruction, and whether decoy-pulse protection is applied.

    Based on Xu/Erata/Szefer (ACM CCS 2023) -- controller power draw and
    4-8 GHz microwave emissions leak the gate sequence; a sufficiently
    sensitive receiver can reconstruct the circuit.

    circuit_profile: {"gate_ops": [...], "decoy_pulses_applied": bool,
                      "distinct_gate_types": int}
    We CANNOT measure real EM here (needs an SDR -- hardware-gated). We audit
    STRUCTURE + PROTECTION: a circuit with few distinct gate types and no
    decoy protection is highly reconstructable.
    """

    def audit(self, circuit_profile: dict) -> dict:
        ops = circuit_profile.get("gate_ops", [])
        decoy = bool(circuit_profile.get("decoy_pulses_applied", False))
        distinct = circuit_profile.get("distinct_gate_types")
        if distinct is None:
            distinct = len({o.get("gate") for o in ops})

        # Reconstructability heuristic: distinct, structured pulse signatures
        # are what a side-channel receiver keys on. Low distinct-gate variety
        # + long circuit = a clean, reconstructable signature.
        reconstructable = (distinct <= 4 and len(ops) >= 3)

        result = {
            "substrate": "quantum",
            "gate_count": len(ops),
            "distinct_gate_types": distinct,
            "decoy_pulses_applied": decoy,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "SideChannelExposureAuditor",
            "cite": "Xu/Erata/Szefer, Power Side-Channel in QC Controllers (CCS 2023)",
        }

        if reconstructable and not decoy:
            result["type"] = "QUANTUM_SIDECHANNEL_EXPOSED"
            result["severity"] = "WARNING"
            result["detail"] = ("circuit structure is reconstructable via "
                                "controller power/EM side channel and no decoy-"
                                "pulse protection is applied")
            result["recommended_action"] = {
                "action": "apply_decoy_pulse_protection_or_flag",
                "risk": "advisory"}
            result["hardware_note"] = ("real EM confirmation needs an SDR near "
                                       "the controller -- this is a structural "
                                       "exposure audit, not a live measurement")
        elif reconstructable and decoy:
            result["type"] = "QUANTUM_SIDECHANNEL_PROTECTED"
            result["severity"] = "INFO"
            result["detail"] = "reconstructable structure but decoy-pulse protection present"
        else:
            result["type"] = "QUANTUM_SIDECHANNEL_LOW_EXPOSURE"
            result["severity"] = "INFO"
        return result


# ---------------------------------------------------------------------------
# 3 -- Multi-tenant crosstalk-attack detector
# ---------------------------------------------------------------------------
class CrosstalkAttackDetector:
    """
    Detect a co-tenant attacking a victim circuit via crosstalk on a shared
    QPU: gate-fidelity degradation or readout-crosstalk inference.

    Based on: SWAP attack (arXiv:2502.10115); Harper et al. crosstalk attacks
    & defence (arXiv:2402.02753); readout crosstalk end-to-end attack
    (ACM QSP Workshop 2025).

    baseline_fidelity: this circuit's known-good fidelity when running alone.
    observed_fidelity: fidelity observed in the current (shared) session.
    neighbor_active: whether a co-tenant is running on adjacent qubits.
    readout_correlation: (optional) measured correlation between this
        circuit's readout and a neighbor's activity (a leak signal).
    """

    def __init__(self, fidelity_drop_threshold=0.10,
                 readout_correlation_threshold=0.3):
        self.fidelity_drop_threshold = fidelity_drop_threshold
        self.readout_correlation_threshold = readout_correlation_threshold

    def detect(self, baseline_fidelity: float, observed_fidelity: float,
               neighbor_active: bool, readout_correlation: float = None) -> dict:
        drop = baseline_fidelity - observed_fidelity
        result = {
            "substrate": "quantum",
            "baseline_fidelity": baseline_fidelity,
            "observed_fidelity": observed_fidelity,
            "fidelity_drop": round(drop, 4),
            "neighbor_active": neighbor_active,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "CrosstalkAttackDetector",
            "cite": "SWAP attack (arXiv:2502.10115); crosstalk attacks & defence (arXiv:2402.02753)",
        }

        signals = []
        if neighbor_active and drop >= self.fidelity_drop_threshold:
            signals.append("FIDELITY_DEGRADATION")
        if (readout_correlation is not None
                and readout_correlation >= self.readout_correlation_threshold):
            signals.append("READOUT_CROSSTALK_LEAK")

        if signals:
            result["type"] = "QUANTUM_CROSSTALK_ATTACK_SUSPECTED"
            result["severity"] = "WARNING"
            result["signals"] = signals
            result["detail"] = ("co-tenant crosstalk consistent with a SWAP / "
                                "crosstalk attack: " + ", ".join(signals))
            result["recommended_action"] = {
                "action": "request_isolated_allocation_and_reraise",
                "risk": "gated"}
        elif neighbor_active:
            result["type"] = "QUANTUM_CROSSTALK_NOMINAL"
            result["severity"] = "INFO"
            result["detail"] = "co-tenant active but no attack-grade degradation"
        else:
            result["type"] = "QUANTUM_NO_NEIGHBOR"
            result["severity"] = "INFO"
        return result


if __name__ == "__main__":
    v = PulseManifestVerifier()
    declared = [{"gate": "h", "qubits": [0]}, {"gate": "cx", "qubits": [0, 1]}]
    tampered = {"gate_ops": [{"gate": "h", "qubits": [0]},
                             {"gate": "x", "qubits": [1]}], "pulse_hash": "abc"}
    print("[Q-1]", v.verify(declared, tampered)["type"])

    a = SideChannelExposureAuditor()
    print("[Q-2]", a.audit({"gate_ops": [{"gate": "h"}] * 5,
                            "decoy_pulses_applied": False})["type"])

    c = CrosstalkAttackDetector()
    print("[Q-3]", c.detect(0.95, 0.80, neighbor_active=True)["type"])
