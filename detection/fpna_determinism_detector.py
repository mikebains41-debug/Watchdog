#!/usr/bin/env python3
"""
fpna_determinism_detector.py -- Floating-Point Non-Associativity (FPNA)
Attack Detector.
Part of Watchdog AI-Attack Detection Suite.

THREAT
------
Shanmugavelu et al. (Euro-Par 2025, arXiv:2503.17173) show that
floating-point non-associativity combined with asynchronous parallel
reduction ordering on GPUs is sufficient to flip a classifier's output
WITHOUT any perturbation to the input. Their black-box variant uses
Bayesian optimization to find an external co-tenant workload that biases
a victim's reduction ordering and reliably induces misclassification,
especially for inputs near the decision boundary. Standard adversarial
robustness results can be overestimated by up to ~4.6% when this
machine-level effect is ignored.

WHAT THIS DETECTS (and what it does NOT)
----------------------------------------
This is a DETERMINISM MONITOR, not a proof of malice. It re-runs an
identical, caller-supplied computation N times and measures run-to-run
variation in the output. On a quiescent GPU, a correctly written
deterministic reduction should produce bit-identical (or within a tight
tolerance) results. Variation ABOVE the tolerance means the output is
order-sensitive right now -- which is the precondition the FPNA attack
exploits. A sustained INCREASE in that variation, correlated with a
co-tenant workload starting, is the actual attack signature.

It cannot, from numerics alone, distinguish "malicious co-tenant biasing
my reductions" from "benign noisy neighbor perturbing scheduling." That
distinction requires the co-tenant/telemetry correlation done by the
caller. This module supplies the numeric-instability half honestly.

REMEDIATION (safe / auto vs. gated)
-----------------------------------
- FPNA_NONDETERMINISM_DETECTED at INFO: log only. Auto-safe.
- FPNA_ATTACK_SUSPECTED (variation crosses the attack threshold AND a
  baseline was previously clean): recommend forcing deterministic mode
  for the affected workload. Enabling deterministic algorithms is a
  low-risk, reversible software action -- eligible for auto-remediation
  IF the caller opts in via auto_remediate=True. Default is gated
  (returns a recommended_action, does not apply it), matching the
  existing human-approval remediation pattern.

The remediation itself (torch.use_deterministic_algorithms(True) and
setting CUBLAS_WORKSPACE_CONFIG) is emitted as a structured action for
the RemediationEngine to execute, NOT performed here, so this detector
stays free of a hard torch dependency and remains unit-testable without
a GPU.
"""

import statistics
from pathlib import Path
import json

BASELINE_STATE = Path("/tmp/watchdog_fpna_baseline.json")

# Relative variation (coefficient of variation of the summary scalar)
# below which we call the computation deterministic. Real deterministic
# GPU reductions are bit-identical (CV == 0); a tiny epsilon absorbs
# legitimate float print/round noise.
DETERMINISTIC_TOLERANCE = 1e-9

# Above this relative variation we treat the output as attack-grade
# unstable: large enough to flip a near-boundary classification.
ATTACK_VARIATION_THRESHOLD = 1e-4


def relative_variation(values: list) -> float:
    """Coefficient of variation (stdev / |mean|) of a list of scalars.
    Returns 0.0 for a single value or an all-identical list."""
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    if mean == 0:
        # fall back to absolute stdev when mean is zero
        return statistics.pstdev(values)
    return statistics.pstdev(values) / abs(mean)


def evaluate_determinism(output_scalars: list,
                          det_tolerance: float = DETERMINISTIC_TOLERANCE,
                          attack_threshold: float = ATTACK_VARIATION_THRESHOLD,
                          baseline_path: Path = BASELINE_STATE,
                          auto_remediate: bool = False) -> dict:
    """
    output_scalars: a list of summary scalars, one per identical re-run of
    the SAME computation on the SAME input (e.g. the logit for the
    predicted class, or a reduction sum). The caller is responsible for
    producing these by running the workload N times; this module does the
    statistics and the classification.

    Returns a status dict. Persists a clean-baseline variation on first
    clean observation so a later rise can be flagged as a transition.
    """
    if not output_scalars or len(output_scalars) < 2:
        return {"status": "SKIPPED",
                "message": "need >= 2 repeated outputs to assess determinism"}

    cv = relative_variation(output_scalars)

    # Load prior clean baseline if present.
    prior = None
    if baseline_path.exists():
        try:
            prior = json.loads(baseline_path.read_text()).get("clean_cv")
        except (json.JSONDecodeError, OSError):
            prior = None

    result = {
        "runs": len(output_scalars),
        "relative_variation": cv,
        "det_tolerance": det_tolerance,
        "attack_threshold": attack_threshold,
        "min": min(output_scalars),
        "max": max(output_scalars),
    }

    if cv <= det_tolerance:
        # Deterministic now. Record/refresh clean baseline.
        try:
            baseline_path.write_text(json.dumps({"clean_cv": cv}))
        except OSError:
            pass
        result["status"] = "FPNA_DETERMINISTIC_OK"
        return result

    if cv >= attack_threshold:
        # Attack-grade instability. If we had previously seen this exact
        # computation as clean, this is a transition -- stronger signal.
        transitioned = prior is not None and prior <= det_tolerance
        result["status"] = "FPNA_ATTACK_SUSPECTED"
        result["transition_from_clean_baseline"] = transitioned
        action = {
            "action": "force_deterministic_algorithms",
            "detail": ("set torch.use_deterministic_algorithms(True) and "
                       "CUBLAS_WORKSPACE_CONFIG=:4096:8 for the affected "
                       "workload; low-risk, reversible"),
            "risk": "low",
        }
        if auto_remediate:
            result["remediation_applied"] = False
            result["remediation_dispatched"] = action
            result["note"] = ("auto_remediate=True: action dispatched to "
                               "RemediationEngine for execution")
        else:
            result["recommended_action"] = action
            result["note"] = "gated: action recommended, not applied"
        return result

    # Non-deterministic but below attack grade: informational.
    result["status"] = "FPNA_NONDETERMINISM_DETECTED"
    result["note"] = ("output is order-sensitive but below attack-flip "
                      "threshold; monitor for correlation with co-tenant start")
    return result


if __name__ == "__main__":
    # Demonstrative synthetic runs (no GPU needed to show the branches).
    clean = [12.340000000, 12.340000000, 12.340000000]
    unstable = [12.3401, 12.3399, 12.3402, 12.3398]
    for label, data in (("clean", clean), ("unstable", unstable)):
        r = evaluate_determinism(data)
        print(f"[FPNA] {label}: {r['status']} "
              f"(cv={r.get('relative_variation'):.2e})")
