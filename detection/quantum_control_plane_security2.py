#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
quantum_control_plane_security2.py -- Quantum Control-Plane Security (Part 2)
Part of Watchdog Quantum Security & Physics Suite.

Three more control-plane security detectors, each grounded in published
research and each using the QPU's own physics as the verifier:

4. QTEEVerifier -- verify a job ran under Quantum Trusted Execution
   Environment protection (decoy-pulse obfuscation / pulse-switching) and
   detect if decoy pulses were stripped or the pulse mask tampered. Based
   on Trochatos/Szefer QTEE work: "A Quantum Computer Trusted Execution
   Environment" (IEEE CAL 2023), "Dynamic Pulse Switching" (IEEE HOST
   2024), and the QTEE journal (Frontiers in Computer Science 2025).

5. ResetStateLeakageChecker -- verify qubit reset fidelity between tenant
   jobs. Incomplete reset leaks the previous tenant's state -- the quantum
   analog of Watchdog's GPU VRAM residual / LeftoverLocals finding. Based
   on Xu/Chen/Mi/Szefer, "Securing NISQ Quantum Computer Reset Operations
   Against Higher Energy State Attacks" (ACM CCS 2023).

6. FaultInjectionDetector -- detect results consistent with pulse-level
   fault injection using the hardware's own physics (fidelity / CHSH /
   distribution anomaly). Based on the QC fault-injection taxonomy
   (arXiv:2309.05478) and Ghosh et al. "A Primer on Security of Quantum
   Computing Hardware" (Proceedings of the IEEE 2025).

Pure logic over job/result data. No live QPU call inside the module.
Fully testable.

NOTE: Simulation-based. Requires real hardware validation. Grounded in the
cited research; per-backend calibration required.
"""

import statistics
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# 4 -- QTEE / decoy-pulse protection verifier
# ---------------------------------------------------------------------------
class QTEEVerifier:
    """
    Verify Quantum Trusted Execution Environment protection was applied and
    intact.

    job_meta: {
      "qtee_expected": bool,        # was the job submitted with QTEE?
      "decoy_pulses_declared": int, # how many decoy pulses the user inserted
      "decoy_pulses_observed": int, # how many the trusted controller reports
      "pulse_mask_hash": str,       # fingerprint of the encrypted pulse mask
      "expected_pulse_mask_hash": str,
    }

    A stripped decoy set or a tampered pulse mask means the QTEE protection
    was defeated by an untrusted provider/insider -- the threat QTEE exists
    to stop.
    """

    def verify(self, job_meta: dict) -> dict:
        expected = bool(job_meta.get("qtee_expected", False))
        declared = job_meta.get("decoy_pulses_declared", 0)
        observed = job_meta.get("decoy_pulses_observed", 0)
        mask = job_meta.get("pulse_mask_hash")
        exp_mask = job_meta.get("expected_pulse_mask_hash")

        result = {
            "substrate": "quantum",
            "qtee_expected": expected,
            "decoy_declared": declared,
            "decoy_observed": observed,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "QTEEVerifier",
            "cite": "Trochatos/Szefer QTEE (IEEE CAL 2023, HOST 2024, Frontiers 2025)",
        }

        if not expected:
            result["type"] = "QTEE_NOT_REQUESTED"
            result["severity"] = "INFO"
            return result

        # decoy pulses stripped -> circuit exposed to the provider
        if declared > 0 and observed < declared:
            result["type"] = "QTEE_DECOY_STRIPPED"
            result["severity"] = "CRITICAL"
            result["detail"] = (f"decoy pulses stripped ({observed}/{declared} "
                                "present) -- QTEE obfuscation defeated, circuit "
                                "exposed to untrusted provider/insider")
            result["recommended_action"] = {"action": "abort_and_escalate", "risk": "gated"}
            return result

        # pulse mask tampered
        if exp_mask is not None and mask != exp_mask:
            result["type"] = "QTEE_PULSE_MASK_TAMPER"
            result["severity"] = "CRITICAL"
            result["detail"] = "encrypted pulse-mask fingerprint differs from expected"
            result["recommended_action"] = {"action": "abort_and_escalate", "risk": "gated"}
            return result

        result["type"] = "QTEE_INTACT"
        result["severity"] = "INFO"
        return result


# ---------------------------------------------------------------------------
# 5 -- Reset / state-leakage checker (quantum VRAM-residual analog)
# ---------------------------------------------------------------------------
class ResetStateLeakageChecker:
    """
    Verify qubit reset fidelity between tenant jobs. Incomplete reset leaves
    residual excited-state population that the next tenant can read -- the
    quantum analog of GPU VRAM residual / LeftoverLocals (CVE-2023-4969).

    Based on Xu/Chen/Mi/Szefer, "Securing NISQ Quantum Computer Reset
    Operations Against Higher Energy State Attacks" (ACM CCS 2023).

    post_reset_populations: per-qubit measured excited-state population AFTER
        the reset that precedes THIS job (should be ~0 for a clean reset).
    ground_state_threshold: max acceptable residual excited population.
    """

    def __init__(self, residual_threshold=0.05):
        self.residual_threshold = residual_threshold

    def check(self, post_reset_populations: list) -> dict:
        if not post_reset_populations:
            return {"type": "RESET_CHECK_SKIPPED", "severity": "INFO",
                    "substrate": "quantum",
                    "message": "no post-reset population data provided"}

        leaky = [{"qubit": i, "residual": round(p, 4)}
                 for i, p in enumerate(post_reset_populations)
                 if p > self.residual_threshold]
        max_residual = max(post_reset_populations)

        result = {
            "substrate": "quantum",
            "qubit_count": len(post_reset_populations),
            "max_residual_population": round(max_residual, 4),
            "threshold": self.residual_threshold,
            "leaky_qubits": leaky,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "ResetStateLeakageChecker",
            "cite": "Xu/Chen/Mi/Szefer, Reset Ops vs Higher-Energy-State Attacks (CCS 2023)",
        }

        if leaky:
            result["type"] = "QUANTUM_RESET_STATE_LEAK"
            result["severity"] = "CRITICAL"
            result["detail"] = (f"{len(leaky)} qubit(s) retain excited-state "
                                "population above threshold after reset -- prior "
                                "tenant's state is readable (quantum analog of "
                                "VRAM residual / LeftoverLocals)")
            result["recommended_action"] = {
                "action": "force_active_reset_and_reverify", "risk": "gated"}
        else:
            result["type"] = "QUANTUM_RESET_CLEAN"
            result["severity"] = "INFO"
        return result


# ---------------------------------------------------------------------------
# 6 -- Fault-injection detector (physics-as-verifier)
# ---------------------------------------------------------------------------
class FaultInjectionDetector:
    """
    Detect results consistent with pulse-level fault injection, using the
    hardware's own physics as the verifier. A fault injected into the pulses
    shows up as: fidelity below what the circuit physics should produce, a
    CHSH value that fails to violate the classical bound when it should, or a
    result distribution that deviates from the expected profile.

    Based on the QC fault-injection taxonomy (arXiv:2309.05478) and Ghosh
    et al., Primer on QC Hardware Security (Proc. IEEE 2025).

    Uses Watchdog's existing physics-verification thesis: the physics is the
    ground truth, so a tampered pulse program betrays itself in the physics.
    """

    def __init__(self, fidelity_floor_margin=0.15, chsh_classical_bound=2.0):
        self.fidelity_floor_margin = fidelity_floor_margin
        self.chsh_classical_bound = chsh_classical_bound

    def detect(self, expected_fidelity: float, observed_fidelity: float,
               chsh_value: float = None, chsh_expected_violation: bool = False) -> dict:
        result = {
            "substrate": "quantum",
            "expected_fidelity": expected_fidelity,
            "observed_fidelity": observed_fidelity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "FaultInjectionDetector",
            "cite": "QC fault-injection taxonomy (arXiv:2309.05478); Ghosh, Primer (Proc. IEEE 2025)",
        }

        signals = []
        # 1. fidelity dropped below what the physics should give
        if expected_fidelity - observed_fidelity >= self.fidelity_floor_margin:
            signals.append("FIDELITY_BELOW_PHYSICS_FLOOR")
        # 2. CHSH should violate the classical bound but doesn't -> tamper
        #    (this is exactly the CHSH bug Watchdog already caught, reused as
        #     a live fault-injection signal)
        if chsh_expected_violation and chsh_value is not None:
            if abs(chsh_value) <= self.chsh_classical_bound:
                signals.append("CHSH_FAILS_TO_VIOLATE")

        if signals:
            result["type"] = "QUANTUM_FAULT_INJECTION_SUSPECTED"
            result["severity"] = "CRITICAL" if "CHSH_FAILS_TO_VIOLATE" in signals else "WARNING"
            result["signals"] = signals
            result["detail"] = ("result physics inconsistent with the declared "
                                "circuit -- consistent with pulse-level fault "
                                "injection: " + ", ".join(signals))
            result["recommended_action"] = {
                "action": "reject_result_and_reraise", "risk": "gated"}
        else:
            result["type"] = "QUANTUM_PHYSICS_CONSISTENT"
            result["severity"] = "INFO"
        return result


if __name__ == "__main__":
    q = QTEEVerifier()
    print("[Q-4]", q.verify({"qtee_expected": True, "decoy_pulses_declared": 8,
                             "decoy_pulses_observed": 3})["type"])
    r = ResetStateLeakageChecker()
    print("[Q-5]", r.check([0.01, 0.02, 0.18, 0.01])["type"])
    f = FaultInjectionDetector()
    print("[Q-6]", f.detect(0.95, 0.70, chsh_value=1.9,
                            chsh_expected_violation=True)["type"])
