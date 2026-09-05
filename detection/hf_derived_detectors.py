#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
hf_derived_detectors.py -- Detectors derived from Hugging Face research (Part 1)
Part of Watchdog AI-Attack Detection Suite.

Two NEW detection classes surfaced by a systematic sweep of Hugging Face
papers (Sep 2026). Neither exists in Watchdog's 41 engines; checked against
the engine list before writing (model_weight_integrity_detector catches
hash DRIFT, not malicious STRUCTURE; ghost-power/CEI catch idle waste, not
adversarially-INDUCED waste).

1. SpectralWeightBackdoorDetector
   Backdoors and poisoning planted in model weights leave characteristic
   signatures in the SINGULAR-VALUE SPECTRUM of weight matrices: a trojan
   is typically a low-rank perturbation, so it (a) inflates a few singular
   values relative to a clean reference, (b) flattens the tail of the
   spectrum, or (c) shifts the effective rank. Zero-shot -- no knowledge of
   the trigger needed. Works on any matrix-shaped weight (linear layers,
   attention projections, LoRA deltas).
   Sources: Z-PEFT "Zero-shot Backdoor Detection in PEFT via Canonical
   Spectral Signatures" (arXiv 2608.02271, Aug 2026); "Watch the Weights:
   Unsupervised monitoring of fine-tuned LLMs via singular vectors of weight
   differences" (2508.00161); Weight Poisoning Attacks (2004.06660).

2. SpongeAttackDetector
   "Sponge examples" are adversarial inputs crafted to MAXIMIZE energy and
   latency -- the payload IS your power bill. They look like a workload but
   deliver little useful output per joule. Detect via energy-per-inference
   and latency-per-inference far above the model's own baseline while
   useful-output-per-joule collapses. Sits at the Watchdog / GPU Optimizer
   boundary; an attack class nobody monitors.
   Source: Sponge Examples: Energy-Latency Attacks on Neural Networks
   (arXiv 2006.03463).

SECURITY REVIEW COMPLIANCE (SECURITY_REVIEW_2026-09-04):
  - no bare `except:` (every catch is `except Exception as e` and surfaced)
  - no shell=True, no subprocess at all
  - detection only; all recommended actions are gated
  - operates on weight STATISTICS and telemetry, never reads tenant data

NOTE: Logic-tested. Spectral thresholds are grounded in the cited papers
but require per-architecture calibration against a clean reference model.
"""

import math
import statistics
from datetime import datetime, timezone

try:
    import numpy as np
    _HAVE_NUMPY = True
except Exception as _e:  # noqa: BLE001 -- surfaced below, not swallowed
    np = None
    _HAVE_NUMPY = False
    _NUMPY_ERR = repr(_e)


# ---------------------------------------------------------------------------
# 1 -- Spectral weight-backdoor detector
# ---------------------------------------------------------------------------
def _singular_values(matrix):
    """Singular values (descending). Requires numpy; caller handles absence."""
    m = np.asarray(matrix, dtype=np.float64)
    if m.ndim != 2:
        m = m.reshape(m.shape[0], -1)
    return np.linalg.svd(m, compute_uv=False)


def spectral_signature(matrix, rank_energy=0.90) -> dict:
    """
    Canonical spectral signature of one weight matrix:
      - top1_ratio: sigma_1 / sum(sigma)   (spike concentration)
      - effective_rank: #singular values needed to capture `rank_energy` of energy
      - tail_flatness: mean(tail) / mean(head) of the spectrum
      - spectral_entropy: entropy of the normalized spectrum (bits)
    """
    s = _singular_values(matrix)
    s = s[s > 0]
    if s.size == 0:
        return {"top1_ratio": 0.0, "effective_rank": 0, "tail_flatness": 0.0,
                "spectral_entropy": 0.0, "n": 0}
    total = float(s.sum())
    p = s / total
    energy = np.cumsum(s ** 2) / float((s ** 2).sum())
    eff_rank = int(np.searchsorted(energy, rank_energy) + 1)
    k = max(1, s.size // 4)
    head = float(s[:k].mean())
    tail = float(s[-k:].mean())
    entropy = float(-(p * np.log2(p)).sum())
    return {
        "top1_ratio": float(s[0] / total),
        "effective_rank": eff_rank,
        "tail_flatness": (tail / head) if head > 0 else 0.0,
        "spectral_entropy": entropy,
        "n": int(s.size),
    }


class SpectralWeightBackdoorDetector:
    """
    Compare a suspect layer's spectral signature against a CLEAN reference
    (the same layer from a trusted checkpoint of the same architecture).
    Fires when the suspect shows the low-rank-perturbation fingerprint.

    Thresholds (defaults from the Z-PEFT / Watch-the-Weights regime; calibrate
    per architecture):
      top1_ratio_inflation   -- suspect top1/reference top1 >= 1.5
      rank_shift_frac        -- |eff_rank change| / reference eff_rank >= 0.25
      entropy_drop_bits      -- reference entropy - suspect entropy >= 0.5
    """

    def __init__(self, top1_ratio_inflation=1.5, rank_shift_frac=0.25,
                 entropy_drop_bits=0.5):
        self.top1_ratio_inflation = top1_ratio_inflation
        self.rank_shift_frac = rank_shift_frac
        self.entropy_drop_bits = entropy_drop_bits
        self.checks = 0
        self.flags = 0

    def analyze(self, layer_name: str, suspect_matrix, reference_matrix=None) -> dict:
        self.checks += 1
        ts = datetime.now(timezone.utc).isoformat()
        base = {"substrate": "model", "layer": layer_name, "timestamp": ts,
                "agent": "SpectralWeightBackdoorDetector",
                "cite": "Z-PEFT (2608.02271); Watch the Weights (2508.00161); Weight Poisoning (2004.06660)"}

        if not _HAVE_NUMPY:
            base.update(type="SPECTRAL_CHECK_UNAVAILABLE", severity="INFO",
                        reason=f"numpy not importable: {_NUMPY_ERR}")
            return base

        try:
            sus = spectral_signature(suspect_matrix)
        except Exception as e:  # surfaced, not swallowed
            base.update(type="SPECTRAL_CHECK_ERROR", severity="WARNING",
                        error=f"{type(e).__name__}: {e}",
                        note="detector failed loud; do NOT treat as clean")
            return base

        base["suspect_signature"] = sus

        if reference_matrix is None:
            # No reference: can only report the signature, not judge it.
            base.update(type="SPECTRAL_SIGNATURE_ONLY", severity="INFO",
                        note="no clean reference supplied; signature recorded, no verdict")
            return base

        try:
            ref = spectral_signature(reference_matrix)
        except Exception as e:
            base.update(type="SPECTRAL_CHECK_ERROR", severity="WARNING",
                        error=f"reference: {type(e).__name__}: {e}")
            return base
        base["reference_signature"] = ref

        signals = []
        if ref["top1_ratio"] > 0 and sus["top1_ratio"] / ref["top1_ratio"] >= self.top1_ratio_inflation:
            signals.append("TOP_SINGULAR_VALUE_INFLATED")     # low-rank spike
        if ref["effective_rank"] > 0 and \
                abs(sus["effective_rank"] - ref["effective_rank"]) / ref["effective_rank"] >= self.rank_shift_frac:
            signals.append("EFFECTIVE_RANK_SHIFTED")
        if ref["spectral_entropy"] - sus["spectral_entropy"] >= self.entropy_drop_bits:
            signals.append("SPECTRAL_ENTROPY_COLLAPSED")     # energy concentrated

        if signals:
            self.flags += 1
            base.update(type="WEIGHT_BACKDOOR_SUSPECTED",
                        severity="CRITICAL" if len(signals) >= 2 else "WARNING",
                        signals=signals,
                        swarm_signal="WEIGHT_BACKDOOR_SUSPECTED",
                        detail=("weight spectrum shows the low-rank-perturbation fingerprint "
                                "of a planted backdoor/poison relative to the clean reference"),
                        recommended_action={"action": "quarantine_model_chmod_000_gated",
                                            "detail": "quarantine (never delete -- evidence); "
                                                      "block load; human review",
                                            "risk": "gated"})
        else:
            base.update(type="WEIGHT_SPECTRUM_CONSISTENT", severity="INFO")
        return base

    def get_stats(self):
        return {"component": "SpectralWeightBackdoorDetector",
                "checks": self.checks, "flags": self.flags, "numpy": _HAVE_NUMPY}


# ---------------------------------------------------------------------------
# 2 -- Sponge / energy-latency attack detector
# ---------------------------------------------------------------------------
class SpongeAttackDetector:
    """
    Seal a per-model baseline of (energy_j per inference, latency_ms per
    inference, useful_output per joule). Then flag inference windows where
    energy AND latency per inference blow past baseline while output/joule
    collapses -- the sponge signature. A legitimately heavy request raises
    energy but ALSO raises useful output; a sponge raises energy for
    nothing.

    Inputs per window: {"inferences": n, "energy_j": total joules,
                        "latency_ms_total": total ms, "useful_tokens": total}
    """

    def __init__(self, model_id: str, energy_inflation=3.0, latency_inflation=3.0,
                 output_per_joule_collapse=0.4):
        self.model_id = model_id
        self.energy_inflation = energy_inflation
        self.latency_inflation = latency_inflation
        self.output_per_joule_collapse = output_per_joule_collapse
        self._baseline = None
        self.checks = 0
        self.flags = 0

    @staticmethod
    def _rates(window: dict):
        n = max(1, int(window.get("inferences", 0)))
        e = float(window.get("energy_j", 0.0))
        lat = float(window.get("latency_ms_total", 0.0))
        tok = float(window.get("useful_tokens", 0.0))
        return {"energy_per_inf": e / n, "latency_per_inf": lat / n,
                "output_per_joule": (tok / e) if e > 0 else 0.0}

    def seal_baseline(self, clean_window: dict) -> dict:
        try:
            self._baseline = self._rates(clean_window)
        except Exception as e:
            return {"type": "SPONGE_BASELINE_FAILED", "error": f"{type(e).__name__}: {e}"}
        return {"type": "SPONGE_BASELINE_SEALED", "model_id": self.model_id,
                "baseline": self._baseline}

    def check(self, window: dict) -> dict:
        self.checks += 1
        ts = datetime.now(timezone.utc).isoformat()
        base = {"substrate": "gpu", "model_id": self.model_id, "timestamp": ts,
                "agent": "SpongeAttackDetector",
                "cite": "Sponge Examples: Energy-Latency Attacks (arXiv 2006.03463)"}
        if self._baseline is None:
            base.update(type="SPONGE_CHECK_SKIPPED", severity="INFO",
                        message="no baseline; call seal_baseline() on clean traffic first")
            return base
        try:
            cur = self._rates(window)
        except Exception as e:
            base.update(type="SPONGE_CHECK_ERROR", severity="WARNING",
                        error=f"{type(e).__name__}: {e}", note="failed loud; not clean")
            return base

        b = self._baseline
        e_ratio = (cur["energy_per_inf"] / b["energy_per_inf"]) if b["energy_per_inf"] > 0 else 0.0
        l_ratio = (cur["latency_per_inf"] / b["latency_per_inf"]) if b["latency_per_inf"] > 0 else 0.0
        o_ratio = (cur["output_per_joule"] / b["output_per_joule"]) if b["output_per_joule"] > 0 else 0.0

        base.update(energy_ratio=round(e_ratio, 2), latency_ratio=round(l_ratio, 2),
                    output_per_joule_ratio=round(o_ratio, 3), current=cur, baseline=b)

        energy_up = e_ratio >= self.energy_inflation
        latency_up = l_ratio >= self.latency_inflation
        output_down = o_ratio <= self.output_per_joule_collapse

        if energy_up and output_down:
            self.flags += 1
            base.update(type="SPONGE_ATTACK_SUSPECTED",
                        severity="CRITICAL" if latency_up else "WARNING",
                        swarm_signal="SPONGE_ATTACK_SUSPECTED",
                        detail=("energy per inference inflated while useful output per "
                                "joule collapsed -- inputs are burning power for nothing "
                                "(energy-latency / sponge signature)"),
                        recommended_action={"action": "rate_limit_or_quarantine_source_gated",
                                            "detail": "throttle the offending client/queue; "
                                                      "preserve samples for analysis; gated",
                                            "risk": "gated"},
                        optimizer_link=("this is adversarially-induced waste -- GPU Optimizer's "
                                        "efficiency gains are the attacker's target"))
        elif energy_up and not output_down:
            base.update(type="HEAVY_BUT_PRODUCTIVE", severity="INFO",
                        detail="energy up but output kept pace -- legitimately heavy work")
        else:
            base.update(type="SPONGE_NOMINAL", severity="INFO")
        return base

    def get_stats(self):
        return {"component": "SpongeAttackDetector", "model_id": self.model_id,
                "sealed": self._baseline is not None, "checks": self.checks, "flags": self.flags}


if __name__ == "__main__":
    if _HAVE_NUMPY:
        rng = np.random.default_rng(1)
        clean = rng.normal(0, 1, (256, 256))
        # plant a low-rank backdoor: rank-1 spike
        u = rng.normal(0, 1, (256, 1)); v = rng.normal(0, 1, (1, 256))
        poisoned = clean + 40.0 * (u @ v)
        d = SpectralWeightBackdoorDetector()
        print("[SPECTRAL] clean-vs-clean:", d.analyze("fc1", clean, clean)["type"])
        print("[SPECTRAL] poisoned:", d.analyze("fc1", poisoned, clean)["type"])
    s = SpongeAttackDetector("llm-v1")
    s.seal_baseline({"inferences": 100, "energy_j": 500, "latency_ms_total": 5000, "useful_tokens": 20000})
    print("[SPONGE] nominal:", s.check({"inferences": 100, "energy_j": 520, "latency_ms_total": 5100, "useful_tokens": 19500})["type"])
    print("[SPONGE] attack:", s.check({"inferences": 100, "energy_j": 2500, "latency_ms_total": 25000, "useful_tokens": 3000})["type"])
