"""
tests/test_vram_residency_challenge.py

Tests the LOGIC of scripts/vram_residency_challenge.py against synthetic
data: latency classification and threshold derivation. This proves the
arithmetic is correct. It proves NOTHING about what real hardware
actually measures, or whether the source paper's >350ms hot/cold gap
holds on any specific GPU -- that requires running the script for real.

Run: python tests/test_vram_residency_challenge.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scripts.vram_residency_challenge import (
    classify_residency,
    compute_cold_threshold,
    median,
    calibrate_thresholds,
    run_challenge,
)

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def test_median_odd_count():
    check("median: odd-count list", median([3, 1, 2]) == 2)


def test_median_even_count():
    check("median: even-count list averages the two middle values",
          median([1, 2, 3, 4]) == 2.5)


def test_median_empty_returns_none():
    check("median: empty list returns None, not a crash",
          median([]) is None)


def test_median_single_value():
    check("median: single-element list", median([7.5]) == 7.5)


def test_cold_threshold_uses_multiplier_when_larger():
    result = compute_cold_threshold(10.0, multiplier=5.0, min_gap_ms=50.0)
    check("cold threshold: uses whichever is larger, multiplier or "
          "min_gap floor", result == 60.0, f"got {result}")


def test_cold_threshold_uses_min_gap_for_tiny_hot_median():
    """A sub-millisecond hot median must not produce a trivially-crossed
    cold threshold -- the min_gap floor exists exactly for this case."""
    result = compute_cold_threshold(0.1, multiplier=5.0, min_gap_ms=50.0)
    check("cold threshold: min_gap floor protects against a tiny hot "
          "median producing an easily-crossed threshold",
          result == 50.1, f"got {result}")


def test_cold_threshold_always_above_hot_median():
    for hot in [0.01, 1.0, 10.0, 100.0, 1000.0]:
        result = compute_cold_threshold(hot)
        check(f"cold threshold always exceeds hot median (hot={hot})",
              result > hot, f"got {result} for hot={hot}")


def test_classify_hot():
    check("classify: at or below hot threshold -> 'hot'",
          classify_residency(5.0, hot_threshold_ms=10.0, cold_threshold_ms=50.0) == 'hot')


def test_classify_cold():
    check("classify: at or above cold threshold -> 'cold'",
          classify_residency(60.0, hot_threshold_ms=10.0, cold_threshold_ms=50.0) == 'cold')


def test_classify_ambiguous():
    """The core honesty check: a measurement between the two thresholds
    must be reported as genuinely ambiguous, not force-fit into hot or
    cold."""
    check("classify: between thresholds -> 'ambiguous', not forced "
          "into a binary answer",
          classify_residency(30.0, hot_threshold_ms=10.0, cold_threshold_ms=50.0) == 'ambiguous')


def test_classify_boundary_exact_hot():
    check("classify: exactly at hot threshold counts as hot (inclusive)",
          classify_residency(10.0, hot_threshold_ms=10.0, cold_threshold_ms=50.0) == 'hot')


def test_classify_boundary_exact_cold():
    check("classify: exactly at cold threshold counts as cold (inclusive)",
          classify_residency(50.0, hot_threshold_ms=10.0, cold_threshold_ms=50.0) == 'cold')


def test_run_challenge_none_when_no_torch():
    latency, mb = run_challenge(torch_module=None)
    check("run_challenge: returns (None, None) cleanly when torch_module "
          "is None (simulating no CUDA available), not a crash",
          latency is None and mb is None)


def test_calibrate_thresholds_none_when_no_gpu():
    hot, cold = calibrate_thresholds(torch_module=None)
    check("calibrate_thresholds: returns (None, None) when no samples "
          "could be collected", hot is None and cold is None)


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for t in tests:
        try:
            t()
        except Exception as e:
            check(t.__name__, False, f"EXCEPTION {e!r}")

    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print("\nFailures:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
