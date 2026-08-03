#!/usr/bin/env python3
"""
M_quantum_drift_tracker.py

Tracks quantum efficiency score (from M_quantum_efficiency_score.py) over
time to detect drift - a fridge or qubit array degrading before it fails
outright. Direct analog to Phase 3's Real-Time CEI Degradation Tracking
(M30) for GPUs.

STATUS: AWAITING_HARDWARE_TEST
This module operates on scores that are themselves AWAITING_HARDWARE_TEST
(see M_quantum_efficiency_score.py). The drift-detection LOGIC is sound
and testable today with synthetic data; the INPUT scores need real
telemetry before any drift alert should be trusted operationally.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import statistics


DRIFT_WARNING_PCT = 10.0
DRIFT_CRITICAL_PCT = 20.0


@dataclass
class ScoreReading:
    timestamp_label: str
    efficiency_score: int


@dataclass
class DriftTracker:
    unit_id: str
    baseline_score: Optional[int] = None
    history: List[ScoreReading] = field(default_factory=list)

    def add_reading(self, reading: ScoreReading):
        if self.baseline_score is None:
            self.baseline_score = reading.efficiency_score
        self.history.append(reading)

    def current_drift_pct(self) -> Optional[float]:
        if self.baseline_score is None or not self.history:
            return None
        latest = self.history[-1].efficiency_score
        if self.baseline_score == 0:
            return None
        return ((self.baseline_score - latest) / self.baseline_score) * 100

    def status(self) -> str:
        drift = self.current_drift_pct()
        if drift is None:
            return "NO_DATA"
        if drift >= DRIFT_CRITICAL_PCT:
            return "CRITICAL_DRIFT"
        if drift >= DRIFT_WARNING_PCT:
            return "WARNING_DRIFT"
        if drift <= -DRIFT_WARNING_PCT:
            return "IMPROVED"
        return "STABLE"

    def trend_slope(self) -> Optional[float]:
        if len(self.history) < 2:
            return None
        scores = [r.efficiency_score for r in self.history]
        n = len(scores)
        x_mean = (n - 1) / 2
        y_mean = statistics.mean(scores)
        numerator = sum((i - x_mean) * (s - y_mean) for i, s in enumerate(scores))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        if denominator == 0:
            return 0.0
        return numerator / denominator


def print_drift_report(tracker: DriftTracker):
    print("-" * 78)
    print("Unit: {}".format(tracker.unit_id))
    if tracker.baseline_score is None:
        print("  STATUS: NO_DATA - no readings recorded yet")
        print("-" * 78)
        return
    print("  Baseline score: {}".format(tracker.baseline_score))
    print("  Latest score:   {}".format(tracker.history[-1].efficiency_score))
    drift = tracker.current_drift_pct()
    print("  Drift from baseline: {:.1f}%".format(drift))
    slope = tracker.trend_slope()
    if slope is not None:
        print("  Trend slope: {:+.2f} points per reading".format(slope))
    print("  STATUS: {}".format(tracker.status()))
    print("-" * 78)


if __name__ == "__main__":
    print("=" * 78)
    print("QUANTUM DRIFT TRACKER - EFFICIENCY SCORE DEGRADATION DETECTION")
    print("STATUS: AWAITING_HARDWARE_TEST (logic tested on synthetic data only)")
    print("=" * 78)

    tracker = DriftTracker(unit_id="FRIDGE-03")
    synthetic_readings = [91, 89, 85, 82, 78, 71]
    for i, score in enumerate(synthetic_readings):
        tracker.add_reading(ScoreReading(timestamp_label="run_{:03d}".format(i), efficiency_score=score))

    print_drift_report(tracker)

    print()
    print("NEXT STEPS TO MOVE THIS OUT OF AWAITING_HARDWARE_TEST:")
    print("  1. Feed real M_quantum_efficiency_score.py outputs over time from")
    print("     an actual operating cryostat, not synthetic scores.")
    print("  2. Calibrate DRIFT_WARNING_PCT / DRIFT_CRITICAL_PCT against real")
    print("     failure precursor data once available - the 10%/20% thresholds")
    print("     are borrowed directly from the GPU M30 roadmap, unvalidated")
    print("     for quantum/cryo degradation patterns specifically.")
    print("  3. Decide on minimum history length before trusting trend_slope()")
    print("     - very short histories will produce noisy, unreliable slopes.")
