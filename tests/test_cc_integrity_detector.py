#!/usr/bin/env python3
# Watchdog
# Author: Manmohan (Mike) Bains -- Watchdog
# Project: GPU Optimizer / Watchdog
#
# Positive Control Test: ConfidentialComputingIntegrityDetector
# ==================================================================
# WHY THIS EXISTS
#   Same rationale as all prior positive control tests tonight. This
#   detector's data source is the real nvidia-smi conf-compute -q
#   command, so this test mocks that subprocess call to confirm the
#   PARSING and STATE-CHANGE logic is correct -- it does NOT confirm
#   behavior against real Confidential Computing hardware.
#
# FIXED: sys.path previously added detection/ directly, but
# cc_integrity_detector.py imports its shared helpers via the
# package-qualified 'from detection._shared import ...', which needs
# the repo root on path instead -- same class of bug already fixed in
# test_positive_controls_advanced.py and test_ecc_error_trend_detector.py
# tonight. Mock patch targets updated to match the new import path.
#
# HONEST STATUS
#   Verified locally (4/4 tests passing) before on-device confirmation.

import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detection.cc_integrity_detector import ConfidentialComputingIntegrityDetector


def test_baseline_establishes_no_alert():
    d = ConfidentialComputingIntegrityDetector(check_interval=0)
    with patch("detection.cc_integrity_detector.subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = "CC status: ON\nOther info: xyz"
        mock_run.return_value = mock_result
        result = d.check(gpu_index=0)
    assert result is None, "FAIL: fired on initial baseline establishment"
    print("[PASS] Baseline establishes correctly with no alert")


def test_on_to_off_fires_critical():
    """Real trigger: CC status transitions from ON to OFF (mocked)."""
    d = ConfidentialComputingIntegrityDetector(check_interval=0)
    with patch("detection.cc_integrity_detector.subprocess.run") as mock_run:
        mock_on = MagicMock()
        mock_on.stdout = "CC status: ON"
        mock_run.return_value = mock_on
        d.check(gpu_index=0)

        mock_off = MagicMock()
        mock_off.stdout = "CC status: OFF"
        mock_run.return_value = mock_off
        result = d.check(gpu_index=0)
    assert result is not None and result["type"] == "CC_STATE_CHANGE" and result["severity"] == "CRITICAL", \
        "FAIL: did not fire CRITICAL on known ON->OFF transition"
    print(f"[PASS] ON->OFF transition fired correctly (mocked): {result['message']}")


def test_stable_state_silent():
    d = ConfidentialComputingIntegrityDetector(check_interval=0)
    result = None
    with patch("detection.cc_integrity_detector.subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = "CC status: ON"
        mock_run.return_value = mock_result
        d.check(gpu_index=0)
        result = d.check(gpu_index=0) or result
    assert result is None, "FAIL: fired on genuinely stable, unchanged CC state"
    print("[PASS] Correctly silent on stable, unchanged state")


def test_unparseable_output_no_false_alert():
    d = ConfidentialComputingIntegrityDetector(check_interval=0)
    with patch("detection.cc_integrity_detector.subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = "garbage unparseable output"
        mock_run.return_value = mock_result
        result = d.check(gpu_index=0)
    assert result is None, "FAIL: fired on unparseable output (should stay silent, not guess)"
    print("[PASS] Correctly silent on unparseable output (no false positive)")


if __name__ == "__main__":
    print("=== Positive Control Test: ConfidentialComputingIntegrityDetector ===\n")
    tests = [
        test_baseline_establishes_no_alert,
        test_on_to_off_fires_critical,
        test_stable_state_silent,
        test_unparseable_output_no_false_alert,
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
