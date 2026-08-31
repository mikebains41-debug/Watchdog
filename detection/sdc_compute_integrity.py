#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
sdc_compute_integrity.py -- Silent Data Corruption / Compute-Integrity (Part 1)
Part of Watchdog AI-Attack Detection Suite.

THE GAP THIS FILLS
------------------
Silent Data Corruption (SDC): hardware computes a WRONG answer with no error
flag. Google "Cores That Don't Count" (HotOS '21) + Meta "SDC at Scale"
(2021): ~1 in 1,000 machines. Soft-error rate went from 1/year at 65nm to
1 per 1.5 hrs at 16nm. Meta attributes 1.4% of Llama-3 training
interruptions to SDC; Google sees an SDC event every 1-2 weeks at Gemini
scale.

NVIDIA's own tools (DCGM / NVSentinel) do HEALTH monitoring + OFFLINE
diagnostics -- they do NOT verify that a running production computation
produced the right answer. "DCGM reports Healthy while the customer gets
garbage." Watchdog's niche = IN-FLIGHT RUNTIME INTEGRITY, complementary to
DCGM, endorsed by the OCP "Silent Data Corruption in AI" whitepaper
(Nishant George, NVIDIA, Dec 2025).

DETECTORS IN THIS MODULE
------------------------
1. DrDNAMonitor (LEAD) -- profile the normal Distribution of Neuron
   Activations offline, flag deviations online. Precision-agnostic (works
   FP8 AND FP4), whole-model, lightweight. Ma et al. "Dr. DNA", ASPLOS '24.

2. NullificationCascadeDetector -- the specific failure signature that
   dominates real SDC: nullification (zeroing) is 50.68% of corruptions,
   and NaN/Inf cascades dominate at FP4 where a bit-flip in an NVFP4
   micro-block scaling factor poisons all 16 packed values at once. Cheap,
   always-on. Cite: "Anatomy of SDC: GPU Error Pattern Study" (2605.04213).

Pure Python + optional numpy fast path. No GPU/torch needed for the logic;
the caller supplies activation statistics from its real inference pipeline
(this keeps it deployable on edge/phone and unit-testable). Fully testable.

NOTE: Simulation-based / logic-tested. Requires real-hardware validation
against a silently-corrupting GPU (which needs an aged/defective card --
same reason Google/Meta hunt "mercurial cores" across millions of
machines). Thresholds grounded in cited research; per-model calibration
required. First-to-PRODUCT, not first-to-idea -- academia is active
(Dr. DNA, ATTNChecker, V-ABFT, FLARE, Meta Hardware Sentinel).
"""

import math
import statistics
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# small stats helpers (stdlib; numpy used only if the caller passes arrays)
# ---------------------------------------------------------------------------
def _mean(xs):
    return statistics.fmean(xs) if xs else 0.0


def _pstdev(xs):
    return statistics.pstdev(xs) if len(xs) > 1 else 0.0


# ---------------------------------------------------------------------------
# 1 -- Dr. DNA activation-distribution monitor (LEAD)
# ---------------------------------------------------------------------------
class DrDNAMonitor:
    """
    Two stages (per Ma et al., ASPLOS '24):

    OFFLINE PROFILING: feed clean, known-good activation samples for a chosen
    cohort of neuron indices; record the healthy distribution signature
    (mean, stdev) per monitored neuron.

    ONLINE DETECTION: during production inference, sample the same neurons.
    If the observed activation deviates from the profiled signature by more
    than `z_threshold` standard deviations, flag SDC.

    Precision-agnostic: it watches the distribution, not the float bits, so
    it works at FP8 and FP4 alike (unlike ABFT, which breaks at NVFP4).
    """

    def __init__(self, z_threshold=6.0, min_profile_samples=30):
        self.z_threshold = z_threshold
        self.min_profile_samples = min_profile_samples
        self._signature = {}   # neuron_id -> {"mean":.., "std":..}
        self.profiled = False
        self.checks = 0
        self.flags = 0

    def profile(self, clean_activations: dict) -> dict:
        """
        clean_activations: {neuron_id: [list of clean activation values]}.
        Builds the healthy signature. Returns a summary.
        """
        sig = {}
        insufficient = []
        for nid, vals in clean_activations.items():
            if len(vals) < self.min_profile_samples:
                insufficient.append(nid)
                continue
            sig[nid] = {"mean": _mean(vals), "std": _pstdev(vals)}
        self._signature = sig
        self.profiled = len(sig) > 0
        return {
            "type": "DRDNA_PROFILE",
            "neurons_profiled": len(sig),
            "insufficient_neurons": insufficient,
            "min_samples": self.min_profile_samples,
            "status": "PROFILED" if self.profiled else "PROFILE_INSUFFICIENT",
        }

    def check(self, observed: dict, auto_remediate: bool = False) -> dict:
        """
        observed: {neuron_id: activation_value} sampled during live inference.
        Flags neurons whose value deviates > z_threshold sigma from profile.
        """
        if not self.profiled:
            return {"type": "DRDNA_SKIPPED", "severity": "INFO",
                    "substrate": "compute",
                    "message": "not profiled; call profile() on clean data first"}

        self.checks += 1
        deviations = []
        for nid, val in observed.items():
            sig = self._signature.get(nid)
            if sig is None:
                continue
            std = sig["std"]
            if std <= 0:
                # a monitored neuron that was constant in profiling; any
                # change is suspicious
                if abs(val - sig["mean"]) > 1e-6:
                    deviations.append({"neuron": nid, "z": float("inf"),
                                       "observed": val, "expected": sig["mean"]})
                continue
            z = abs(val - sig["mean"]) / std
            if z >= self.z_threshold:
                deviations.append({"neuron": nid, "z": round(z, 2),
                                   "observed": val, "expected": round(sig["mean"], 4)})

        result = {
            "substrate": "compute",
            "neurons_checked": len(observed),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "DrDNAMonitor",
            "cite": "Ma et al., Dr. DNA (ASPLOS '24)",
        }
        if deviations:
            self.flags += 1
            result["type"] = "SDC_CORRUPTION_DETECTED"
            result["severity"] = "CRITICAL"
            result["method"] = "activation_distribution_deviation"
            result["deviations"] = deviations[:20]
            result["deviation_count"] = len(deviations)
            action = {"action": "gated_rerun_and_flag_batch",
                      "detail": "re-run affected batch (jittered timing) and raise; "
                                "do NOT emit the corrupted output to the client",
                      "risk": "gated"}
            if auto_remediate:
                result["remediation_dispatched"] = action
            else:
                result["recommended_action"] = action
            result["note"] = ("in-flight runtime integrity; precision-agnostic; "
                              "simulation-based, per-model calibration required")
        else:
            result["type"] = "COMPUTE_INTEGRITY_OK"
            result["severity"] = "INFO"
        return result

    def get_stats(self):
        return {"component": "DrDNAMonitor", "profiled": self.profiled,
                "neurons": len(self._signature), "checks": self.checks,
                "flags": self.flags}


# ---------------------------------------------------------------------------
# 2 -- Nullification / NaN / Inf cascade detector
# ---------------------------------------------------------------------------
class NullificationCascadeDetector:
    """
    Catches the dominant real-world SDC signatures cheaply, always-on:

    - NULLIFICATION: a corrupted op zeroes its output. 50.68% of SDCs.
      Flagged when the fraction of exact-zero elements exceeds
      `zero_fraction_threshold` (a healthy dense activation is rarely ~all
      zero).
    - NaN / Inf CASCADE: at FP4/NVFP4, a bit-flip in a micro-block scaling
      factor poisons all 16 packed values -> immediate overflow. Any NaN or
      Inf in an activation tensor that should be finite is a hard flag.

    The caller passes lightweight summary stats (zero_fraction, has_nan,
    has_inf) computed from its tensor -- so this stays framework-agnostic
    and unit-testable without a GPU. On a real deployment these come from a
    vectorized CUDA reduction (torch.sum(t==0)/t.numel(), torch.isnan, etc.)
    run on a non-blocking stream.
    """

    def __init__(self, zero_fraction_threshold=0.95, precision="fp8"):
        self.zero_fraction_threshold = zero_fraction_threshold
        self.precision = precision
        self.checks = 0
        self.flags = 0

    def check(self, zero_fraction: float, has_nan: bool = False,
              has_inf: bool = False, precision: str = None,
              auto_remediate: bool = False) -> dict:
        self.checks += 1
        prec = precision or self.precision
        signals = []
        if has_nan:
            signals.append("NAN_CASCADE")
        if has_inf:
            signals.append("INF_CASCADE")
        if zero_fraction is not None and zero_fraction >= self.zero_fraction_threshold:
            signals.append("NULLIFICATION")

        result = {
            "substrate": "compute",
            "precision": prec,
            "zero_fraction": zero_fraction,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "NullificationCascadeDetector",
            "cite": "Anatomy of SDC: GPU Error Pattern Study (2605.04213)",
        }
        if signals:
            self.flags += 1
            result["type"] = "SDC_CORRUPTION_DETECTED"
            result["severity"] = "CRITICAL"
            result["method"] = "nullification_nan_inf_cascade"
            result["signals"] = signals
            # FP4 note: scaling-factor poisoning makes cascades more likely
            if prec in ("fp4", "nvfp4"):
                result["fp4_note"] = ("NVFP4 micro-block scaling-factor bit-flip "
                                      "poisons all 16 packed values -> cascade")
            action = {"action": "gated_rerun_and_flag_batch",
                      "detail": "drop corrupted output, re-run batch, raise",
                      "risk": "gated"}
            if auto_remediate:
                result["remediation_dispatched"] = action
            else:
                result["recommended_action"] = action
        else:
            result["type"] = "COMPUTE_INTEGRITY_OK"
            result["severity"] = "INFO"
        return result

    def get_stats(self):
        return {"component": "NullificationCascadeDetector",
                "checks": self.checks, "flags": self.flags}


if __name__ == "__main__":
    # Dr. DNA demo
    dna = DrDNAMonitor(z_threshold=6.0)
    import random
    random.seed(1)
    clean = {i: [random.gauss(0, 1) for _ in range(50)] for i in range(5)}
    print("[SDC-1]", dna.profile(clean)["status"])
    print("[SDC-1] clean:", dna.check({i: 0.1 for i in range(5)})["type"])
    print("[SDC-1] corrupt:", dna.check({0: 50.0, 1: 0.1, 2: 0.1, 3: 0.1, 4: 0.1})["type"])

    # Nullification demo
    nc = NullificationCascadeDetector(precision="nvfp4")
    print("[SDC-2] null:", nc.check(zero_fraction=0.99)["type"])
    print("[SDC-2] nan:", nc.check(zero_fraction=0.1, has_nan=True)["type"])
    print("[SDC-2] ok:", nc.check(zero_fraction=0.1)["type"])
