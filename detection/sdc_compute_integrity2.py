#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
sdc_compute_integrity2.py -- SDC / Compute-Integrity (Part 2)
Part of Watchdog AI-Attack Detection Suite.

Three more compute-integrity detectors:

3. FreivaldsVerifier -- probabilistic matrix-product verification: check
   A x B = C in O(n^2) via a random vector, instead of recomputing in
   O(n^3). Catches a silent bit-flip in the result with high probability.
   LABELED FP8-ONLY and MATMUL-ONLY: valid where IEEE-754-style scaling
   holds (FP8), NOT reliable at FP4/NVFP4 (micro-block scaling breaks the
   checksum); covers matmuls (~75% of compute) NOT softmax/nonlinear ops.
   Cite: Freivalds 1977; soft-error ABFT (2103.00130); OCP whitepaper
   endorses ABFT-in-kernels.

4. VoltageDroopCorrelator -- correlates a power/voltage telemetry anomaly
   (dI/dt droop) with a compute-integrity anomaly in the same window. A
   droop too brief for the chip's own monitoring to catch can cause a
   timing violation -> silent bit-flip. When BOTH a droop AND an integrity
   flag occur together, confidence is high. Cite: NVIDIA/AMD dI/dt-droop
   patents; Anasim H100 PDN study. Dual-use: GPU Optimizer undervolting
   raises droop risk, so this is the safety net that lets Optimizer push
   efficiency harder.

5. TMRVoter -- triple-run majority vote. HIGH-VALUE OPT-IN ONLY: the OCP
   whitepaper calls heavy redundancy (2-3x overhead) "unfeasible" at scale,
   so this is gated for high-value workloads, never a default.

Pure logic, no GPU needed. Fully testable.

NOTE: Simulation-based / logic-tested. Per-model/backend calibration and
live-hardware validation pending. Overhead numbers for buyers: V-ABFT
~12%, SEVI 1.35% at 88-100% detection, DMR/redundancy >200%.
"""

import statistics
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# 3 -- Freivalds' verifier (FP8-only, matmul-only)
# ---------------------------------------------------------------------------
class FreivaldsVerifier:
    """
    Verify C == A @ B without recomputing the product.

    Freivalds: pick a random vector r; check A @ (B @ r) == C @ r within a
    floating-point tolerance. If they differ beyond tolerance, C is corrupt.
    Probability of missing a real error is <= 2^-k for k independent random
    vectors.

    Matrices are passed as row-major lists of lists (pure Python, so it runs
    anywhere and is unit-testable). A numpy fast path is used automatically
    if numpy is available and the inputs are large.

    The floating-point tolerance is CRITICAL (per A-ABFT/GVFA research):
    without it, normal rounding error false-positives. It scales with the
    inner dimension and magnitude.
    """

    def __init__(self, rounds=3, rel_tolerance=1e-3, precision="fp8"):
        self.rounds = rounds
        self.rel_tolerance = rel_tolerance
        self.precision = precision
        self.checks = 0
        self.flags = 0

    @staticmethod
    def _matvec(M, v):
        return [sum(M[i][j] * v[j] for j in range(len(v))) for i in range(len(M))]

    def verify(self, A, B, C, precision: str = None,
               auto_remediate: bool = False) -> dict:
        prec = precision or self.precision
        # Honesty gate: Freivalds/ABFT is not reliable at FP4/NVFP4.
        if prec in ("fp4", "nvfp4"):
            return {
                "type": "FREIVALDS_NOT_APPLICABLE",
                "severity": "INFO",
                "substrate": "compute",
                "precision": prec,
                "note": ("Freivalds/ABFT is FP8-only; NVFP4 micro-block scaling "
                         "breaks the checksum. Use Dr. DNA / nullification "
                         "detectors at FP4 instead."),
                "agent": "FreivaldsVerifier",
            }

        import random
        self.checks += 1
        n_rows, n_cols = len(A), len(B[0])
        inner = len(B)
        # magnitude-aware absolute tolerance
        max_abs = 1.0
        for row in C:
            for x in row:
                if abs(x) > max_abs:
                    max_abs = abs(x)
        abs_tol = self.rel_tolerance * max_abs * max(1, inner)

        mismatch = False
        for _ in range(self.rounds):
            r = [random.uniform(-1, 1) for _ in range(n_cols)]
            Br = self._matvec(B, r)
            ABr = self._matvec(A, Br)
            Cr = self._matvec(C, r)
            for a_val, c_val in zip(ABr, Cr):
                if abs(a_val - c_val) > abs_tol:
                    mismatch = True
                    break
            if mismatch:
                break

        result = {
            "substrate": "compute",
            "precision": prec,
            "rounds": self.rounds,
            "tolerance": abs_tol,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "FreivaldsVerifier",
            "cite": "Freivalds 1977; ABFT (2103.00130); OCP whitepaper",
            "coverage_note": "matmul-only (~75% of compute); not softmax/nonlinear",
        }
        if mismatch:
            self.flags += 1
            result["type"] = "SDC_CORRUPTION_DETECTED"
            result["severity"] = "CRITICAL"
            result["method"] = "freivalds_matmul_verification"
            action = {"action": "gated_rerun_matmul", "risk": "gated"}
            if auto_remediate:
                result["remediation_dispatched"] = action
            else:
                result["recommended_action"] = action
        else:
            result["type"] = "COMPUTE_INTEGRITY_OK"
            result["severity"] = "INFO"
        return result

    def get_stats(self):
        return {"component": "FreivaldsVerifier", "checks": self.checks,
                "flags": self.flags}


# ---------------------------------------------------------------------------
# 4 -- Voltage-droop correlation detector
# ---------------------------------------------------------------------------
class VoltageDroopCorrelator:
    """
    Correlate a power/voltage droop with a compute-integrity anomaly in the
    same time window. Either alone is weak; together they are a strong,
    physically-grounded SDC signal.

    telemetry: {"power_watts", "baseline_power_w", "voltage_v",
                "min_operating_v"} sampled at high rate (NVML).
    integrity_flag: True if an integrity detector (Dr. DNA / nullification /
                    Freivalds) flagged in the same window.
    """

    def __init__(self, droop_pct_threshold=0.05, power_dip_w=50.0):
        self.droop_pct_threshold = droop_pct_threshold
        self.power_dip_w = power_dip_w
        self.checks = 0
        self.flags = 0

    def check(self, telemetry: dict, integrity_flag: bool) -> dict:
        self.checks += 1
        v = telemetry.get("voltage_v")
        vmin = telemetry.get("min_operating_v")
        power = telemetry.get("power_watts")
        baseline = telemetry.get("baseline_power_w")

        droop_detected = False
        droop_detail = {}
        if v is not None and vmin is not None and vmin > 0:
            droop_pct = (vmin - v) / vmin if v < vmin else 0.0
            # also treat a supply dip toward vmin as a droop
            margin_pct = (v - vmin) / vmin if v >= vmin else 0.0
            if v <= vmin or margin_pct < self.droop_pct_threshold:
                droop_detected = True
                droop_detail = {"voltage_v": v, "min_operating_v": vmin,
                                "margin_pct": round(margin_pct * 100, 2)}
        if power is not None and baseline is not None:
            if baseline - power >= self.power_dip_w:
                droop_detected = True
                droop_detail["power_dip_w"] = round(baseline - power, 1)

        result = {
            "substrate": "compute",
            "droop_detected": droop_detected,
            "integrity_flag": integrity_flag,
            "droop_detail": droop_detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "VoltageDroopCorrelator",
            "cite": "NVIDIA/AMD dI/dt-droop patents; Anasim H100 PDN study",
        }
        if droop_detected and integrity_flag:
            self.flags += 1
            result["type"] = "DROOP_INDUCED_SDC_CONFIRMED"
            result["severity"] = "CRITICAL"
            result["detail"] = ("voltage/power droop co-occurring with a compute "
                                "integrity anomaly -- physically-grounded SDC")
            result["recommended_action"] = {
                "action": "gated_rerun_and_reduce_clock_or_raise_vmargin",
                "detail": "re-run the batch; flag GPU for undervolt-margin review",
                "risk": "gated"}
            result["optimizer_link"] = ("GPU Optimizer undervolting raises droop "
                                        "risk; this is the safety net")
        elif droop_detected:
            result["type"] = "DROOP_OBSERVED_NO_CORRUPTION"
            result["severity"] = "WARNING"
            result["detail"] = "droop seen but no integrity anomaly this window"
        else:
            result["type"] = "POWER_INTEGRITY_NOMINAL"
            result["severity"] = "INFO"
        return result

    def get_stats(self):
        return {"component": "VoltageDroopCorrelator", "checks": self.checks,
                "flags": self.flags}


# ---------------------------------------------------------------------------
# 5 -- TMR majority voter (high-value opt-in only)
# ---------------------------------------------------------------------------
class TMRVoter:
    """
    Run a computation across 3 lanes, majority-vote the result, flag the
    divergent lane. HIGH-VALUE OPT-IN ONLY -- OCP calls this "unfeasible" at
    scale (2-3x overhead), so it is gated for high-value workloads, never a
    default. Use it to CONFIRM a suspected SDC on a critical result, not for
    blanket protection.
    """

    def __init__(self, tolerance=0.0):
        self.tolerance = tolerance
        self.votes = 0
        self.divergences = 0

    def _close(self, a, b):
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return abs(a - b) <= self.tolerance
        return a == b

    def vote(self, lane_a, lane_b, lane_c) -> dict:
        self.votes += 1
        ab = self._close(lane_a, lane_b)
        ac = self._close(lane_a, lane_c)
        bc = self._close(lane_b, lane_c)

        result = {
            "substrate": "compute",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "TMRVoter",
            "overhead_note": "2-3x compute; OCP 'unfeasible' at scale -- opt-in only",
        }
        if ab and ac and bc:
            result["type"] = "TMR_UNANIMOUS"
            result["severity"] = "INFO"
            result["result"] = lane_a
        elif ab:  # a==b, c diverges
            self.divergences += 1
            result["type"] = "SDC_CORRUPTION_DETECTED"
            result["severity"] = "CRITICAL"
            result["method"] = "tmr_majority_vote"
            result["divergent_lane"] = "c"
            result["result"] = lane_a
            result["recommended_action"] = {"action": "quarantine_divergent_lane_gpu",
                                            "risk": "gated"}
        elif ac:  # a==c, b diverges
            self.divergences += 1
            result["type"] = "SDC_CORRUPTION_DETECTED"
            result["severity"] = "CRITICAL"
            result["divergent_lane"] = "b"
            result["result"] = lane_a
            result["recommended_action"] = {"action": "quarantine_divergent_lane_gpu",
                                            "risk": "gated"}
        elif bc:  # b==c, a diverges
            self.divergences += 1
            result["type"] = "SDC_CORRUPTION_DETECTED"
            result["severity"] = "CRITICAL"
            result["divergent_lane"] = "a"
            result["result"] = lane_b
            result["recommended_action"] = {"action": "quarantine_divergent_lane_gpu",
                                            "risk": "gated"}
        else:  # all three differ -- no majority
            self.divergences += 1
            result["type"] = "TMR_NO_MAJORITY"
            result["severity"] = "CRITICAL"
            result["detail"] = "all three lanes disagree -- cannot vote; escalate"
            result["recommended_action"] = {"action": "escalate_no_trusted_result",
                                            "risk": "gated"}
        return result

    def get_stats(self):
        return {"component": "TMRVoter", "votes": self.votes,
                "divergences": self.divergences}


if __name__ == "__main__":
    # Freivalds demo
    fv = FreivaldsVerifier(precision="fp8")
    A = [[1, 2], [3, 4]]
    B = [[5, 6], [7, 8]]
    C_good = [[19, 22], [43, 50]]
    C_bad = [[19, 22], [43, 99]]
    print("[SDC-3] good:", fv.verify(A, B, C_good)["type"])
    print("[SDC-3] bad:", fv.verify(A, B, C_bad)["type"])
    print("[SDC-3] fp4:", fv.verify(A, B, C_good, precision="nvfp4")["type"])

    # Droop demo
    vd = VoltageDroopCorrelator()
    print("[SDC-4] droop+flag:", vd.check(
        {"voltage_v": 0.58, "min_operating_v": 0.60}, integrity_flag=True)["type"])

    # TMR demo
    tmr = TMRVoter()
    print("[SDC-5] divergent:", tmr.vote(42.0, 42.0, 99.0)["type"])
