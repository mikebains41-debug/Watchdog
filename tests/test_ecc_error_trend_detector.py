#!/usr/bin/env python3
# Watchdog AIDR
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer / Watchdog
#
# Positive Control Test: ECCErrorTrendDetector
# ================================================
# WHY THIS EXISTS
#   Same rationale as all prior positive control tests tonight: proves
#   the detector fires on known-positive patterns and stays silent on
#   clean data, using synthetic values matching the real nvidia-smi
#   ECC field names -- no attack code, no real hardware required.
#
# HONEST STATUS
#   Verified locally (4/4 tests passing) before on-device confirmation.

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
from ecc_error_trend_detector import ECCErrorTrendDetector


def make_row(corrected=0, uncorrected=0, index=0):
    return {
        "ecc.errors.corrected.volatile.total": corrected,
        "ecc.errors.uncorrected.volatile.total": uncorrected,
        "iso_timestamp": "2026-01-01T00:00:00Z",
        "index": index,
    }


def test_uncorrectable_error_fires():
    """Real trigger: ANY increase in uncorrectable ECC error count."""
    d = ECCErrorTrendDetector()
    d.update(make_row(uncorrected=0))
    result = d.update(make_row(uncorrected=1))
    assert result is not None and result["type"] == "ECC_UNCORRECTABLE_ERROR", \
        "FAIL: did not fire on known uncorrectable ECC error"
    print(f"[PASS] Uncorrectable ECC error fired correctly: {result['message']}")


def test_correctable_trend_fires():
    """Real trigger: rising correctable ECC error rate over the window."""
    d = ECCErrorTrendDetector(correctable_rate_threshold=5, window=10)
    result = None
    for i in range(10):
        result = d.update(make_row(corrected=i * 2)) or result
    assert result is not None and result["type"] == "ECC_CORRECTABLE_TREND", \
        "FAIL: did not fire on known rising correctable ECC trend"
    print(f"[PASS] Correctable ECC trend fired correctly: {result['message']}")


def test_silent_on_healthy_gpu():
    d = ECCErrorTrendDetector(correctable_rate_threshold=5, window=10)
    result = None
    for i in range(10):
        result = d.update(make_row(corrected=0, uncorrected=0)) or result
    assert result is None, "FAIL: fired on genuinely healthy GPU (zero errors)"
    print("[PASS] Correctly silent on healthy GPU (zero errors)")


def test_silent_on_flat_low_error_count():
    d = ECCErrorTrendDetector(correctable_rate_threshold=5, window=10)
    result = None
    for i in range(10):
        result = d.update(make_row(corrected=3)) or result
    assert result is None, "FAIL: fired on flat, non-rising low error count"
    print("[PASS] Correctly silent on flat low error count")


if __name__ == "__main__":
    print("=== Positive Control Test: ECCErrorTrendDetector ===\n")
    tests = [
        test_uncorrectable_error_fires,
        test_correctable_trend_fires,
        test_silent_on_healthy_gpu,
        test_silent_on_flat_low_error_count,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {t.__name__}: {e}")
            failed += 1

    print(f"\n=== SUMMARY: {passed}/{len(tests)} passed, {failed} failed ===")
    if failed:
        sys.exit(1)
