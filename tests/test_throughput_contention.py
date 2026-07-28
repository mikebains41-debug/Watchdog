# Author: Manmohan (Mike) Bains -- Watchdog
"""
Tests for ThroughputContentionDetector: paired positive and negative controls.

Run: python tests/test_throughput_contention.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.throughput_contention_detector import ThroughputContentionDetector

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def test_positive_real_documented_event():
    """The actual measured event: 372.32 -> 336.96 iter/sec (-9.5%)."""
    d = ThroughputContentionDetector(baseline_window=5, drop_threshold_pct=8.0)
    for _ in range(5):
        d.calibrate(372.32)
    check("calibrated after 5 clean samples", d.calibrated)

    alert = None
    for _ in range(3):
        alert = d.update(336.96)
    check("POSITIVE: fires on the real documented -9.5% sustained event",
          alert is not None and alert['type'] == 'THROUGHPUT_CONTENTION',
          f"got {alert}")
    if alert:
        check("pct_change matches the real measured drop (~-9.5%)",
              -9.7 <= alert['pct_change'] <= -9.3,
              f"got {alert['pct_change']}")


def test_negative_normal_jitter():
    """+-3% jitter around baseline. Must NOT fire."""
    d = ThroughputContentionDetector(baseline_window=10, drop_threshold_pct=8.0)
    for _ in range(10):
        d.calibrate(370.0)

    alerts = []
    for i in range(200):
        sample = 370.0 * (1 + (0.03 if i % 2 == 0 else -0.03))
        a = d.update(sample)
        if a:
            alerts.append(a)
    check("NEGATIVE: silent on +-3% normal jitter",
          len(alerts) == 0,
          f"fired {len(alerts)} times on jitter -- FALSE POSITIVE")


def test_negative_no_calibration_no_action():
    """update() before calibrate() must do nothing, not auto-calibrate."""
    d = ThroughputContentionDetector(baseline_window=5, drop_threshold_pct=8.0)
    alert = d.update(50.0)
    check("NEGATIVE: update() before calibration returns None, doesn't guess",
          alert is None and not d.calibrated,
          f"got alert={alert}, calibrated={d.calibrated}")


def test_calibration_resists_poisoning():
    """One contended sample during calibration must not collapse the baseline."""
    d = ThroughputContentionDetector(baseline_window=10, drop_threshold_pct=8.0)
    for v in [370, 371, 369, 372, 368, 370, 371, 369, 370, 200]:
        d.calibrate(v)
    check("baseline: median resists a single poisoned calibration sample",
          d.baseline_throughput >= 360,
          f"baseline collapsed to {d.baseline_throughput}")


def test_edge_triggered():
    """A sustained 200-sample contention event must not emit 200 alerts."""
    d = ThroughputContentionDetector(baseline_window=5, drop_threshold_pct=8.0,
                                      require_consecutive=3, refire_after_s=120)
    for _ in range(5):
        d.calibrate(372.32)

    alerts = [d.update(336.96, now=i * 1.0) for i in range(200)]
    fired = [a for a in alerts if a]
    check("edge-triggered: 200-sample sustained event does not emit 200 alerts",
          len(fired) <= 5,
          f"emitted {len(fired)} alerts for one sustained event")


def test_severity_scales_with_drop():
    d = ThroughputContentionDetector(baseline_window=5, drop_threshold_pct=8.0)
    for _ in range(5):
        d.calibrate(400.0)
    mild = None
    for _ in range(3):
        mild = d.update(360.0)
    check("severity MEDIUM for a moderate drop", mild is not None and mild['severity'] == 'MEDIUM',
          f"got {mild}")


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
