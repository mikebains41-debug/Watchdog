#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
model_drift_monitor.py -- Continuous Model Integrity (Part 1)
Model-Drift Monitor + Risk-Tiered Model Register
Part of Watchdog AI-Attack Detection Suite.

WHY (regulatory convergence, verified Aug 2026)
-----------------------------------------------
Pharma, insurance/finance, and government regulators now demand the SAME
thing: continuous model-performance monitoring with drift detection,
revalidation triggers, and audit-ready evidence.

- OSFI E-23 (final Sep 11 2025, effective May 1 2027 -- extends to INSURERS
  for the first time): "ongoing monitoring... breaches of model performance
  (material errors, drifts, threshold violations)" must TRIGGER a review.
  Requires a current MODEL INVENTORY with risk rating by autonomy, data-input
  reliability, customer impact, regulatory risk.
- SR 26-2 (Fed/OCC/FDIC, April 2026, replaced SR 11-7): "metric thresholds
  so drift and decay raise an alert instead of waiting for the next review."
- FDA (Jan 2025 draft; Jan 2026 FDA/EMA joint "Good AI Practice"):
  "prospective validation and ongoing monitoring" for high-risk AI; every AI
  affecting GxP data must be validated with audit trails.
- NIST AI RMF / FedRAMP: "continuous monitoring and regular reassessment."

Watchdog already monitors HARDWARE integrity (SDC catches sudden corruption).
This adds MODEL integrity OVER TIME (gradual drift/decay) -- together they
form full integrity-over-time, which is exactly what the regulators wrote.

DETECTORS IN THIS MODULE
------------------------
1. ModelDriftMonitor -- tracks a deployed model's output distribution and
   a performance metric over time against a sealed baseline; detects
   distribution drift (PSI-style) and performance decay (metric drop);
   fires a REVALIDATION signal when a threshold is crossed. Calibration
   anchor from the research: an LSTM AUC decay 0.9205 -> 0.8579 (delta
   -0.0626) under out-of-time evaluation is a documented "retrain" trigger.

2. ModelRiskRegister -- the E-23 / SR 26-2 required model inventory: every
   model cataloged with owner, purpose, inputs, methodology, limitations,
   and a risk TIER computed from E-23's stated dimensions (autonomy, data-
   input reliability, customer impact, regulatory risk). Extends Watchdog's
   AIBOM (provenance) into a regulatory register.

Pure stdlib, no ML libraries required. Fully testable.

NOTE: Logic-tested. Regulatory clause mapping is stated per detector; this is
monitoring tooling that PRODUCES compliance evidence -- it is not legal
advice and does not by itself constitute regulatory compliance.
"""

import math
import statistics
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# 1 -- Model drift monitor
# ---------------------------------------------------------------------------
def population_stability_index(baseline_bins: list, current_bins: list,
                               eps: float = 1e-6) -> float:
    """PSI between two binned distributions (lists of proportions summing ~1).
    Industry rule of thumb: <0.1 stable, 0.1-0.25 moderate shift, >0.25 significant."""
    if len(baseline_bins) != len(current_bins) or not baseline_bins:
        return float("nan")
    psi = 0.0
    for b, c in zip(baseline_bins, current_bins):
        b = max(b, eps)
        c = max(c, eps)
        psi += (c - b) * math.log(c / b)
    return psi


def _bin_proportions(values: list, edges: list) -> list:
    """Bin numeric values into proportions using the given edges."""
    if not values:
        return [0.0] * (len(edges) - 1)
    counts = [0] * (len(edges) - 1)
    for v in values:
        placed = False
        for i in range(len(edges) - 1):
            lo, hi = edges[i], edges[i + 1]
            last = (i == len(edges) - 2)
            if (lo <= v < hi) or (last and v == hi):
                counts[i] += 1
                placed = True
                break
        if not placed:
            # out of range: clamp to nearest bin
            counts[0 if v < edges[0] else -1] += 1
    n = len(values)
    return [c / n for c in counts]


class ModelDriftMonitor:
    """
    Seal a baseline of (a) the model's output distribution and (b) a
    performance metric (e.g. AUC/accuracy) at validation time. Then, per
    monitoring window, compare current outputs/metric to the baseline.

    Emits:
      MODEL_STABLE                 -- within thresholds
      MODEL_DRIFT_DETECTED         -- output distribution shifted (PSI)
      MODEL_PERFORMANCE_DECAY      -- metric dropped beyond threshold
      MODEL_REVALIDATION_REQUIRED  -- drift or decay crossed the trigger
    Each result cites the regulatory clause it serves.
    """

    def __init__(self, model_id: str, psi_warn=0.10, psi_trigger=0.25,
                 metric_decay_trigger=0.05, bins=10):
        self.model_id = model_id
        self.psi_warn = psi_warn
        self.psi_trigger = psi_trigger
        self.metric_decay_trigger = metric_decay_trigger
        self.bins = bins
        self._edges = None
        self._baseline_bins = None
        self._baseline_metric = None
        self.sealed = False
        self.checks = 0
        self.flags = 0

    def seal_baseline(self, baseline_outputs: list, baseline_metric: float = None) -> dict:
        """Seal the validation-time output distribution + metric."""
        if not baseline_outputs:
            return {"type": "DRIFT_BASELINE_FAILED", "reason": "no baseline outputs"}
        lo, hi = min(baseline_outputs), max(baseline_outputs)
        if hi == lo:
            hi = lo + 1e-6
        step = (hi - lo) / self.bins
        self._edges = [lo + i * step for i in range(self.bins + 1)]
        self._baseline_bins = _bin_proportions(baseline_outputs, self._edges)
        self._baseline_metric = baseline_metric
        self.sealed = True
        return {"type": "DRIFT_BASELINE_SEALED", "model_id": self.model_id,
                "n": len(baseline_outputs), "baseline_metric": baseline_metric,
                "timestamp": datetime.now(timezone.utc).isoformat()}

    def check(self, current_outputs: list, current_metric: float = None) -> dict:
        if not self.sealed:
            return {"type": "DRIFT_CHECK_SKIPPED", "severity": "INFO",
                    "model_id": self.model_id,
                    "message": "no sealed baseline; call seal_baseline() first"}
        self.checks += 1
        signals = []

        current_bins = _bin_proportions(current_outputs, self._edges) if current_outputs else None
        psi = population_stability_index(self._baseline_bins, current_bins) if current_bins else float("nan")

        if current_bins and not math.isnan(psi):
            if psi >= self.psi_trigger:
                signals.append("DISTRIBUTION_DRIFT_SIGNIFICANT")
            elif psi >= self.psi_warn:
                signals.append("DISTRIBUTION_DRIFT_MODERATE")

        metric_delta = None
        if current_metric is not None and self._baseline_metric is not None:
            metric_delta = current_metric - self._baseline_metric
            if metric_delta <= -self.metric_decay_trigger:
                signals.append("PERFORMANCE_DECAY")

        revalidate = ("DISTRIBUTION_DRIFT_SIGNIFICANT" in signals
                      or "PERFORMANCE_DECAY" in signals)

        if revalidate:
            status = "MODEL_REVALIDATION_REQUIRED"
            severity = "CRITICAL"
        elif signals:
            status = "MODEL_DRIFT_DETECTED"
            severity = "WARNING"
        else:
            status = "MODEL_STABLE"
            severity = "INFO"
        if signals:
            self.flags += 1

        return {
            "type": status,
            "severity": severity,
            "model_id": self.model_id,
            "psi": None if math.isnan(psi) else round(psi, 4),
            "metric_baseline": self._baseline_metric,
            "metric_current": current_metric,
            "metric_delta": None if metric_delta is None else round(metric_delta, 4),
            "signals": signals,
            "revalidation_required": revalidate,
            "swarm_signal": "MODEL_REVALIDATION_REQUIRED" if revalidate else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "ModelDriftMonitor",
            "regulatory_clause": [
                "OSFI E-23: monitoring must detect drifts/threshold breaches and trigger review",
                "SR 26-2: metric thresholds so drift/decay raise an alert",
                "FDA/EMA Good AI Practice (Jan 2026): ongoing monitoring for high-risk AI",
                "NIST AI RMF: continuous monitoring",
            ],
            "calibration_anchor": ("documented out-of-time AUC decay 0.9205->0.8579 "
                                   "(delta -0.0626) = retrain trigger (arXiv 2605.04076)"),
            "note": "Logic-tested; thresholds require per-model calibration. Not legal advice.",
        }

    def get_stats(self):
        return {"component": "ModelDriftMonitor", "model_id": self.model_id,
                "sealed": self.sealed, "checks": self.checks, "flags": self.flags}


# ---------------------------------------------------------------------------
# 2 -- Risk-tiered model register (E-23 / SR 26-2 model inventory)
# ---------------------------------------------------------------------------
# E-23's stated risk-rating dimensions. Each scored 1 (low) .. 3 (high).
RISK_DIMENSIONS = ("autonomy", "data_input_reliability_risk",
                   "customer_impact", "regulatory_risk")

REQUIRED_INVENTORY_FIELDS = ("owner", "purpose", "inputs", "methodology", "limitations")


def compute_risk_tier(scores: dict) -> str:
    """Aggregate E-23 dimension scores into a tier. Max-dimension logic:
    a single HIGH dimension makes the model high-risk (regulators' intent)."""
    vals = [int(scores.get(d, 1)) for d in RISK_DIMENSIONS]
    top = max(vals) if vals else 1
    avg = sum(vals) / len(vals) if vals else 1
    if top >= 3 or avg >= 2.5:
        return "HIGH"
    if top >= 2 or avg >= 1.5:
        return "MEDIUM"
    return "LOW"


class ModelRiskRegister:
    """The regulatory model inventory. Every registered model must carry the
    required fields; missing ones are flagged as inventory gaps (an E-23 /
    SR 26-2 finding in itself)."""

    def __init__(self):
        self._models = {}

    def register(self, model_id: str, metadata: dict, risk_scores: dict = None,
                 third_party: bool = False, feeder_models: list = None) -> dict:
        missing = [f for f in REQUIRED_INVENTORY_FIELDS if not metadata.get(f)]
        tier = compute_risk_tier(risk_scores or {})
        entry = {
            "model_id": model_id,
            "metadata": metadata,
            "risk_scores": risk_scores or {},
            "risk_tier": tier,
            "third_party": third_party,
            "feeder_models": feeder_models or [],
            "inventory_gaps": missing,
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "last_validated": metadata.get("last_validated"),
        }
        self._models[model_id] = entry
        return {
            "type": "MODEL_REGISTERED" if not missing else "MODEL_REGISTERED_WITH_GAPS",
            "model_id": model_id,
            "risk_tier": tier,
            "inventory_gaps": missing,
            "regulatory_clause": [
                "OSFI E-23: current model inventory with owner/purpose/inputs/methodology/limitations + risk rating",
                "SR 26-2: model inventory and risk-based tiering",
                "OSFI B-10 (via E-23): third-party model governance incl. feeder models",
            ],
        }

    def get(self, model_id: str):
        return self._models.get(model_id)

    def inventory(self) -> dict:
        by_tier = {"HIGH": [], "MEDIUM": [], "LOW": []}
        gaps = {}
        for mid, e in self._models.items():
            by_tier[e["risk_tier"]].append(mid)
            if e["inventory_gaps"]:
                gaps[mid] = e["inventory_gaps"]
        return {
            "type": "MODEL_INVENTORY",
            "model_count": len(self._models),
            "by_tier": by_tier,
            "third_party_models": [m for m, e in self._models.items() if e["third_party"]],
            "inventory_gaps": gaps,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": "E-23/SR 26-2 model inventory. Gaps are compliance findings. Not legal advice.",
        }


if __name__ == "__main__":
    import random
    random.seed(1)
    m = ModelDriftMonitor("claims-model-v1")
    base = [random.gauss(0.5, 0.1) for _ in range(1000)]
    print("[DRIFT]", m.seal_baseline(base, baseline_metric=0.9205)["type"])
    print("[DRIFT] stable:", m.check([random.gauss(0.5, 0.1) for _ in range(500)], 0.918)["type"])
    print("[DRIFT] decayed:", m.check([random.gauss(0.72, 0.1) for _ in range(500)], 0.8579)["type"])

    reg = ModelRiskRegister()
    r = reg.register("claims-model-v1",
                     {"owner": "risk-team", "purpose": "claims triage", "inputs": "claim text",
                      "methodology": "gradient boosting", "limitations": "no rare-event coverage"},
                     risk_scores={"autonomy": 3, "data_input_reliability_risk": 2,
                                  "customer_impact": 3, "regulatory_risk": 3})
    print("[REGISTER]", r["type"], "tier:", r["risk_tier"])
