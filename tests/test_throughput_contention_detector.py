#!/usr/bin/env python3
# Watchdog AIDR
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer / Watchdog
#
# Validates ThroughputContentionDetector against the REAL, already-measured
# numbers from validation_results/contention_benchmark_note.md:
#   Baseline: 372.32 iter/sec
#   Contention: 336.96 iter/sec
#   Real measured change: -9.5%
#
# This confirms the new detector's logic would have correctly fired on
# the exact real event that validation_results/SUMMARY.md documented as
# missed by all 24 existing Watchdog detectors.

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
from throughput_contention_detector import ThroughputContentionDetector

REAL_BASELINE = 372.32
REAL_CONTENTION = 336.96
REAL_PCT_CHANGE = -9.5


def test_fires_on_real_measured_event():
    """The core test: does this detector catch the real event Watchdog missed?"""
    detector = ThroughputContentionDetector(baseline_window=1, drop_threshold_pct=5.0)
    detector.calibrate(REAL_BASELINE)
    result = detector.update(REAL_CONTENTION, gpu_index=0, timestamp="2026-06-21T00:00:00Z")

    assert result is not None, "FAIL: detector did not fire on the real measured contention event"
    assert result["type"] == "THROUGHPUT_CONTENTION"
    assert abs(result["pct_change"] - REAL_PCT_CHANGE) < 0.1, (
        f"FAIL: detector computed {result['pct_change']}% but real measured value was {REAL_PCT_CHANGE}%"
    )
    print(f"[PASS] Detector correctly fired on real event: {result['message']}")
    return True


def test_silent_on_normal_fluctuation():
    """Negative control: normal small variance should NOT trigger an alert."""
    detector = ThroughputContentionDetector(baseline_window=1, drop_threshold_pct=5.0)
    detector.calibrate(REAL_BASELINE)
    normal_sample = REAL_BASELINE * 0.99  # ~1% dip, normal noise
    result = detector.update(normal_sample, gpu_index=0)

    assert result is None, "FAIL: detector fired on normal noise, too sensitive"
    print("[PASS] Detector correctly stayed silent on normal fluctuation")
    return True


def test_silent_during_baseline_calibration():
    """First sample should calibrate, not alert."""
    detector = ThroughputContentionDetector(baseline_window=1, drop_threshold_pct=5.0)
    result = detector.update(REAL_BASELINE)
    assert result is None, "FAIL: detector alerted during its own calibration sample"
    print("[PASS] Detector correctly stayed silent during calibration")
    return True


if __name__ == "__main__":
    print("=== Validating ThroughputContentionDetector against real Watchdog benchmark data ===\n")
    tests = [
        test_silent_during_baseline_calibration,
        test_fires_on_real_measured_event,
        test_silent_on_normal_fluctuation,
    ]
    results = [t() for t in tests]

    print(f"\n=== SUMMARY: {sum(results)}/{len(results)} tests passed ===")
    if all(results):
        print("This detector closes the gap identified in validation_results/SUMMARY.md:")
        print("the real -9.5% contention event that all 24 existing detectors missed")
        print("is now correctly detected by this new, purpose-built detector.")
    else:
        sys.exit(1)
