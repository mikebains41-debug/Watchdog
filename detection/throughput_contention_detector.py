#!/usr/bin/env python3
# Watchdog AIDR
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
# Project: GPU Optimizer / Watchdog
#
# ThroughputContentionDetector
# =============================
# WHY THIS EXISTS
#   validation_results/SUMMARY.md documented a real, measured, reproducible
#   -9.5% throughput drop under GPU contention (372.32 -> 336.96 iter/sec).
#   The 0%-util detectors in engines.py cannot see this: they only evaluate
#   samples where utilization.gpu == 0, and this event was measured while
#   both tenants were actively computing. Not a tuning problem -- a
#   structural coverage gap. This detector watches throughput itself,
#   during active load, instead of power/util at idle.
#
# FIXED vs. original version (see git history):
#   - Was level-triggered: fired on every sample below threshold. A
#     10-minute contention event produced hundreds of alerts.
#   - Baseline was silently auto-calibrated from whatever 5 samples update()
#     saw first, with no guard against those samples being contended. A
#     poisoned baseline meant the detector could permanently miss real
#     contention below the inflated floor.
#   - Was not wired into DetectionPipeline and had no tests -- the "HONEST
#     STATUS" comment described one manual check against a hardcoded
#     historical value, not a test suite.
#
# STILL UNRESOLVED, stated rather than hidden:
#   drop_threshold_pct default below is set below the one documented real
#   event (-9.5%) but above zero. Normal throughput jitter for a given
#   workload has not been measured. This threshold has not been validated
#   against a real negative control on hardware and should be tuned once
#   that data exists.

from collections import deque
from detection._shared import _EventState


class ThroughputContentionDetector:
    """
    Detects sustained throughput degradation under active GPU load -- the
    gap the 0%-util detectors in engines.py cannot see.

    Calibration is explicit and separate from detection. Call calibrate()
    only with samples you have verified are uncontended. update() will not
    calibrate itself and will not evaluate until calibrate() has supplied
    baseline_window samples.
    """

    def __init__(self, baseline_window=10, drop_threshold_pct=8.0,
                 require_consecutive=3, refire_after_s=120):
        self.baseline_window = baseline_window
        self.drop_threshold_pct = drop_threshold_pct
        self.baseline_samples = deque(maxlen=baseline_window)
        self.baseline_throughput = None
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    @property
    def calibrated(self):
        return self.baseline_throughput is not None

    def calibrate(self, throughput_sample):
        """
        Feed a sample YOU have verified is uncontended. Baseline is the
        median of the window, not the mean: a single contended sample
        entering calibration cannot poison the floor the way a mean would.
        """
        self.baseline_samples.append(throughput_sample)
        if len(self.baseline_samples) >= self.baseline_window:
            vals = sorted(self.baseline_samples)
            self.baseline_throughput = vals[len(vals) // 2]

    def update(self, throughput_sample, gpu_index=0, timestamp=None, now=None):
        """
        Evaluate a sample against the calibrated baseline. Returns an alert
        dict on a sustained drop, or None. Does nothing -- does not
        calibrate, does not evaluate -- until calibrate() has been called
        explicitly with enough samples.
        """
        if self.baseline_throughput is None or self.baseline_throughput <= 0:
            return None

        pct_change = ((throughput_sample - self.baseline_throughput)
                       / self.baseline_throughput) * 100

        condition = pct_change <= -self.drop_threshold_pct
        if not self.state.should_emit(condition, now=now):
            return None

        return {
            "type": "THROUGHPUT_CONTENTION",
            "severity": "MEDIUM" if pct_change > -15 else "HIGH",
            "gpu": gpu_index,
            "baseline_iter_sec": round(self.baseline_throughput, 2),
            "observed_iter_sec": round(throughput_sample, 2),
            "pct_change": round(pct_change, 1),
            "timestamp": timestamp,
            "message": (
                f"Throughput dropped {abs(pct_change):.1f}% below calibrated "
                f"baseline ({self.baseline_throughput:.2f} -> "
                f"{throughput_sample:.2f} iter/sec) during active load -- "
                f"consistent with noisy-neighbor contention."
            ),
        }
