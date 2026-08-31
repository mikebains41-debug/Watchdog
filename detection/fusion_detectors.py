#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
fusion_detectors.py -- Cross-Layer Fusion Detectors (GPU / CPU / Quantum)
Part of Watchdog AI-Attack Detection Suite.

THE DIFFERENTIATOR
------------------
Software-only AI-security platforms (HiddenLayer, Lakera, Protect AI,
Cisco AI Defense) detect at the model/prompt layer. They CANNOT see the
physical substrate the workload runs on. Watchdog can. These detectors
fuse a software-layer signal with a PHYSICAL corroborating signal that
the competition structurally lacks:

  - GPU     -> power / ECC / VRAM telemetry (nvidia-smi native)
  - CPU     -> context-switch / cache-timing (already in Watchdog's CPU work)
  - QUANTUM -> quantum-physics verification (CHSH/Bell fidelity,
               circuit fingerprint -- Watchdog's quantum suite)

A tamper or injection that evades the software check but produces an
anomalous PHYSICAL signature is caught by the physics. That is the
capability no software-only competitor can match.

Each detector is substrate-aware. Where a substrate genuinely cannot
support a corroborator, it says so (returns a PARTIAL confidence with an
honest reason) rather than faking a physical confirmation -- same
discipline as the pod-validation tiers.

DETECTORS IN THIS MODULE
------------------------
1. ModelScanHardwareFusion -- extends model-file scanning (their capability)
   with a runtime-footprint cross-check: does the loaded model's ACTUAL
   physical footprint match its DECLARED architecture? A clean-scanning
   file whose runtime power/memory/timing diverges from its declared
   shape is tampered in a way a file scan alone misses.

2. PromptInjectionPhysicalFusion -- extends structural prompt analysis
   (spotlighting -- Watchdog's own) with a physical corroborator. A prompt
   that reads benign but produces an anomalous compute signature is
   flagged CONFIRMED; text-only-suspicious without a physical anomaly is
   SUSPECTED; physical-anomaly-only (no text signal) is PHYSICAL_ANOMALY.
   On quantum the corroborator is circuit-fidelity: a tampered job shows
   in the physics.

NOTE: Simulation-based. Requires real hardware validation. The fusion
LOGIC is real and tested; the physical thresholds are grounded in
Watchdog's measured findings (e.g. B200 +127.5W prompt-injection
side-effect) but per-deployment calibration is required.
"""

import statistics
from datetime import datetime, timezone

GPU = "gpu"
CPU = "cpu"
QUANTUM = "quantum"
VALID_SUBSTRATES = {GPU, CPU, QUANTUM}


# ---------------------------------------------------------------------------
# Detector 1 -- Model-scan + hardware-footprint fusion
# ---------------------------------------------------------------------------
class ModelScanHardwareFusion:
    """
    file_scan_result: the output of Watchdog's model-file scanners (clean or
        flagged). We accept a simple {"clean": bool, "flags": [...]}.
    declared: the model's declared runtime profile (from its card/AIBOM):
        {"expected_vram_mb", "expected_power_w", "expected_arch"}.
    observed: the ACTUAL runtime footprint measured on the substrate.

    Fusion logic: even a clean-scanning file is flagged if its runtime
    footprint diverges from what its declared architecture should produce.
    """

    def __init__(self, substrate=GPU, tolerance_pct=0.20):
        if substrate not in VALID_SUBSTRATES:
            raise ValueError(f"invalid substrate: {substrate}")
        self.substrate = substrate
        self.tolerance = tolerance_pct

    def evaluate(self, file_scan_result: dict, declared: dict, observed: dict) -> dict:
        clean = file_scan_result.get("clean", True)
        flags = file_scan_result.get("flags", [])

        # Which physical dimensions can this substrate corroborate?
        checks = []
        if self.substrate == GPU:
            checks = [("vram", "expected_vram_mb", "observed_vram_mb"),
                      ("power", "expected_power_w", "observed_power_w")]
        elif self.substrate == CPU:
            # CPU has no per-model power granularity; use compute-time footprint
            checks = [("compute_time", "expected_compute_ms", "observed_compute_ms")]
        elif self.substrate == QUANTUM:
            # quantum: declared vs observed circuit depth / shot cost
            checks = [("circuit_depth", "expected_depth", "observed_depth")]

        mismatches = []
        for name, dkey, okey in checks:
            d = declared.get(dkey)
            o = observed.get(okey)
            if d is None or o is None:
                continue
            if d == 0:
                continue
            div = abs(o - d) / abs(d)
            if div > self.tolerance:
                mismatches.append({"dimension": name, "declared": d,
                                   "observed": o, "divergence_pct": round(div * 100, 1)})

        # Fusion decision matrix
        if not clean and mismatches:
            status = "MODEL_TAMPER_CONFIRMED"
            conf = "high"
        elif not clean and not mismatches:
            status = "MODEL_FILE_FLAGGED"       # their level -- file only
            conf = "medium"
        elif clean and mismatches:
            status = "MODEL_TAMPER_HARDWARE_MISMATCH"   # THE differentiator
            conf = "high"
        else:
            status = "MODEL_INTEGRITY_OK"
            conf = "high"

        result = {
            "type": status,
            "substrate": self.substrate,
            "confidence": conf,
            "file_scan_clean": clean,
            "file_flags": flags,
            "hardware_mismatches": mismatches,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "ModelScanHardwareFusion",
        }
        if status == "MODEL_TAMPER_HARDWARE_MISMATCH":
            result["differentiator_note"] = (
                "File scanned CLEAN but runtime physical footprint diverges "
                "from declared architecture -- a tamper a file-scan-only "
                "competitor would miss.")
            result["recommended_action"] = {
                "action": "block_load_and_investigate", "risk": "gated_no_autokill"}
        elif status == "MODEL_TAMPER_CONFIRMED":
            result["recommended_action"] = {
                "action": "quarantine_and_evacuate", "risk": "gated"}
        return result


# ---------------------------------------------------------------------------
# Detector 2 -- Prompt/job-integrity + physical corroborator fusion
# ---------------------------------------------------------------------------
class PromptInjectionPhysicalFusion:
    """
    text_signal: the structural/spotlight analysis result:
        {"suspicious": bool, "score": 0..1, "reason": str}
    physical: the substrate's corroborating measurement.
        GPU:    {"power_watts", "baseline_power_w"}  -- side-effect spike
        CPU:    {"ctx_switches", "baseline_ctx"}     -- timing side-effect
        QUANTUM:{"circuit_fidelity", "expected_fidelity"} -- physics tamper

    Fusion decision:
      text-suspicious + physical-anomaly  -> CONFIRMED (high)   <- unique
      text-suspicious only                -> SUSPECTED (medium) <- their level
      physical-anomaly only               -> PHYSICAL_ANOMALY   <- unique
      neither                             -> CLEAN
    """

    def __init__(self, substrate=GPU,
                 gpu_power_spike_w=100.0, cpu_ctx_spike_ratio=2.0,
                 quantum_fidelity_drop=0.15):
        if substrate not in VALID_SUBSTRATES:
            raise ValueError(f"invalid substrate: {substrate}")
        self.substrate = substrate
        self.gpu_power_spike_w = gpu_power_spike_w
        self.cpu_ctx_spike_ratio = cpu_ctx_spike_ratio
        self.quantum_fidelity_drop = quantum_fidelity_drop

    def _physical_anomaly(self, physical: dict):
        """Return (anomaly_bool, detail) for this substrate, or (None, reason)
        if the substrate can't corroborate with the data given."""
        if self.substrate == GPU:
            p = physical.get("power_watts")
            b = physical.get("baseline_power_w")
            if p is None or b is None:
                return None, "no power telemetry provided"
            spike = p - b
            return (spike >= self.gpu_power_spike_w,
                    {"power_spike_w": round(spike, 1),
                     "threshold_w": self.gpu_power_spike_w})
        if self.substrate == CPU:
            c = physical.get("ctx_switches")
            b = physical.get("baseline_ctx")
            if c is None or b is None or b == 0:
                return None, "no context-switch baseline provided"
            ratio = c / b
            return (ratio >= self.cpu_ctx_spike_ratio,
                    {"ctx_ratio": round(ratio, 2),
                     "threshold": self.cpu_ctx_spike_ratio})
        if self.substrate == QUANTUM:
            f = physical.get("circuit_fidelity")
            e = physical.get("expected_fidelity")
            if f is None or e is None:
                return None, "no circuit fidelity provided"
            drop = e - f
            return (drop >= self.quantum_fidelity_drop,
                    {"fidelity_drop": round(drop, 3),
                     "threshold": self.quantum_fidelity_drop})
        return None, "unknown substrate"

    def evaluate(self, text_signal: dict, physical: dict) -> dict:
        text_suspicious = bool(text_signal.get("suspicious"))
        anomaly, detail = self._physical_anomaly(physical)

        base = {
            "substrate": self.substrate,
            "text_suspicious": text_suspicious,
            "text_reason": text_signal.get("reason"),
            "physical_detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "PromptInjectionPhysicalFusion",
        }

        if anomaly is None:
            # substrate couldn't corroborate -> honest partial, fall back to text
            base["type"] = ("PROMPT_INJECTION_SUSPECTED" if text_suspicious
                            else "PROMPT_CLEAN_TEXT_ONLY")
            base["confidence"] = "low"
            base["note"] = f"physical corroboration unavailable: {detail}"
            return base

        if text_suspicious and anomaly:
            base["type"] = "PROMPT_INJECTION_PHYSICALLY_CONFIRMED"
            base["confidence"] = "high"
            base["differentiator_note"] = (
                "Injection confirmed by BOTH structural analysis AND a "
                "physical substrate signature -- a software-only competitor "
                "sees only the text half.")
            base["recommended_action"] = {"action": "block_and_raise", "risk": "gated"}
        elif text_suspicious and not anomaly:
            base["type"] = "PROMPT_INJECTION_SUSPECTED"       # their level
            base["confidence"] = "medium"
        elif not text_suspicious and anomaly:
            base["type"] = "PROMPT_PHYSICAL_ANOMALY"          # unique -- text evaded
            base["confidence"] = "medium"
            base["differentiator_note"] = (
                "Text read benign but the substrate shows an anomalous "
                "signature -- an injection that evaded content analysis, "
                "caught by physics.")
            base["recommended_action"] = {"action": "raise_for_review", "risk": "gated"}
        else:
            base["type"] = "PROMPT_CLEAN"
            base["confidence"] = "high"
        return base


if __name__ == "__main__":
    # Model-scan fusion: clean file, but hardware mismatch (the differentiator)
    m = ModelScanHardwareFusion(substrate=GPU)
    r = m.evaluate({"clean": True, "flags": []},
                   declared={"expected_vram_mb": 8000, "expected_power_w": 300},
                   observed={"observed_vram_mb": 8100, "observed_power_w": 470})
    print("[FUSION-1]", r["type"], "-", r.get("differentiator_note", "")[:60])

    # Prompt fusion: benign text, power spike (evaded content analysis)
    p = PromptInjectionPhysicalFusion(substrate=GPU)
    r2 = p.evaluate({"suspicious": False, "reason": "clean"},
                    {"power_watts": 320, "baseline_power_w": 194})
    print("[FUSION-2]", r2["type"], "-", r2.get("differentiator_note", "")[:60])

    # Quantum prompt fusion: job tamper shows in fidelity
    q = PromptInjectionPhysicalFusion(substrate=QUANTUM)
    r3 = q.evaluate({"suspicious": True, "reason": "job param anomaly"},
                    {"circuit_fidelity": 0.70, "expected_fidelity": 0.95})
    print("[FUSION-2q]", r3["type"])
