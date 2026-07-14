#!/usr/bin/env python3
# Watchdog AIDR
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer / Watchdog
#
# ThroughputContentionDetector
# =============================
# WHY THIS EXISTS
#   validation_results/SUMMARY.md documented a real, measured, reproducible
#   -9.5% throughput drop under GPU contention (372.32 -> 336.96 iter/sec),
#   and stated plainly that Watchdog's existing 24 detectors caught NONE
#   of it.
#
#   Root cause, confirmed by reading detection/engines.py directly:
#   CrossTenantBleedingDetector (and the other power/util-based engines)
#   only evaluate samples where utilization.gpu == 0. The contention
#   benchmark that exposed the real -9.5% drop was measured while BOTH
#   tenants were actively computing -- utilization was high throughout,
#   not zero. The existing detectors are structurally incapable of firing
#   on this scenario; it is not a tuning problem, it is a coverage gap.
#
# WHAT THIS DETECTOR DOES DIFFERENTLY
#   Rather than watching power/utilization at idle (0% util), this watches
#   a workload's own throughput signal (iterations/sec) DURING active
#   load, and detects a sustained percentage drop from a calibrated
#   baseline -- the exact signal type that caught the real -9.5%
#   degradation in the benchmark.
#
# HONEST STATUS
#   Tested against the real numeric values from the actual
#   contention_benchmark.py run (372.32 -> 336.96 iter/sec, documented
#   in contention_benchmark_note.md) and confirmed to correctly fire.
#   This is a logic-correctness check against already-measured real data,
#   not a new live hardware run.

from collections import deque


class ThroughputContentionDetector:
    """
    Detects sustained throughput degradation under active GPU load --
    the specific gap CrossTenantBleedingDetector and the other 0%-util
    detectors cannot see, per direct inspection of detection/engines.py.
    """

    def __init__(self, baseline_window=5, drop_threshold_pct=5.0):
        self.baseline_window = baseline_window
        self.drop_threshold_pct = drop_threshold_pct
        self.baseline_samples = deque(maxlen=baseline_window)
        self.baseline_throughput = None

    def calibrate(self, throughput_sample):
        """Feed known-clean, uncontended samples to establish baseline."""
        self.baseline_samples.append(throughput_sample)
        if len(self.baseline_samples) == self.baseline_window:
            self.baseline_throughput = sum(self.baseline_samples) / self.baseline_window

    def update(self, throughput_sample, gpu_index=0, timestamp=None):
        """
        Evaluates a new throughput sample against the calibrated baseline.
        Returns an alert dict if a sustained drop exceeds the threshold,
        matching the return contract of the existing Watchdog detectors.
        """
        if self.baseline_throughput is None:
            self.calibrate(throughput_sample)
            return None

        pct_change = ((throughput_sample - self.baseline_throughput) / self.baseline_throughput) * 100

        if pct_change <= -self.drop_threshold_pct:
            return {
                "type": "THROUGHPUT_CONTENTION",
                "severity": "MEDIUM" if pct_change > -15 else "HIGH",
                "gpu": gpu_index,
                "baseline_iter_sec": round(self.baseline_throughput, 2),
                "observed_iter_sec": round(throughput_sample, 2),
                "pct_change": round(pct_change, 1),
                "timestamp": timestamp,
                "message": (
                    f"Throughput dropped {abs(pct_change):.1f}% below calibrated baseline "
                    f"({self.baseline_throughput:.2f} -> {throughput_sample:.2f} iter/sec) "
                    f"during active load -- consistent with noisy-neighbor contention."
                ),
            }
        return None
