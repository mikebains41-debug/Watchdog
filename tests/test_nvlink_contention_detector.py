# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_nvlink_contention_detector.py

Tests for NVLinkContentionDetector -- learned baseline, edge-triggered,
including the honest negative control matching its own disclosed
discrimination gap (normal collective-communication bursts must not
fire if they're within the learned baseline's normal variance).

Run: python tests/test_nvlink_contention_detector.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.hardware_attacks import NVLinkContentionDetector

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def row(**kw):
    base = {'index': 0, 'iso_timestamp': '2026-07-21T00:00:00',
            'nvlink_available': True}
    base.update(kw)
    return base


def test_silent_when_nvlink_unavailable():
    """Most GPUs (L40S, RTX-series, T4, most single-GPU rentals) have
    no NVLink hardware at all -- must stay silent, not error or
    fabricate a reading."""
    d = NVLinkContentionDetector(baseline_min_samples=5, require_consecutive=2)
    alerts = []
    for _ in range(10):
        alerts.append(d.update(row(nvlink_available=False,
                                    **{'utilization.gpu': 5})))
    fired = [a for a in alerts if a]
    check("NVLINK: silent when nvlink_available is False (no hardware)",
          len(fired) == 0, f"fired {len(fired)} times")


def test_negative_stable_low_traffic():
    """Baseline learned at a stable low-traffic idle floor -- small
    natural variance around it must not fire."""
    d = NVLinkContentionDetector(baseline_min_samples=30, require_consecutive=5,
                                  delta_threshold_kbs=1000.0)
    for _ in range(30):
        d.update(row(**{'utilization.gpu': 5}, nvlink_tx_kbs=100, nvlink_rx_kbs=100))
    alerts = []
    for i in range(10):
        variance = (i % 3) * 10
        alerts.append(d.update(row(**{'utilization.gpu': 5},
                                    nvlink_tx_kbs=100 + variance, nvlink_rx_kbs=100)))
    fired = [a for a in alerts if a]
    check("NVLINK NEGATIVE: silent on small normal traffic variance "
          "around the learned baseline",
          len(fired) == 0, f"fired {len(fired)} times -- FALSE POSITIVE")


def test_positive_sustained_elevated_traffic_at_low_util():
    d = NVLinkContentionDetector(baseline_min_samples=30, require_consecutive=5,
                                  delta_threshold_kbs=1000.0)
    for _ in range(30):
        d.update(row(**{'utilization.gpu': 5}, nvlink_tx_kbs=100, nvlink_rx_kbs=100))
    alerts = [d.update(row(**{'utilization.gpu': 5},
                            nvlink_tx_kbs=5000, nvlink_rx_kbs=5000))
              for _ in range(6)]
    fired = [a for a in alerts if a]
    check("NVLINK POSITIVE: fires on sustained large traffic elevation "
          "at low compute utilization",
          len(fired) >= 1 and fired[0]['type'] == 'NVLINK_CONTENTION',
          f"got {len(fired)} fired")


def test_negative_silent_when_util_is_high():
    """High compute utilization alongside NVLink traffic is exactly the
    normal, expected multi-GPU compute pattern -- must not fire."""
    d = NVLinkContentionDetector(baseline_min_samples=30, require_consecutive=5,
                                  delta_threshold_kbs=1000.0)
    for _ in range(30):
        d.update(row(**{'utilization.gpu': 5}, nvlink_tx_kbs=100, nvlink_rx_kbs=100))
    alerts = [d.update(row(**{'utilization.gpu': 80},
                            nvlink_tx_kbs=5000, nvlink_rx_kbs=5000))
              for _ in range(6)]
    fired = [a for a in alerts if a]
    check("NVLINK NEGATIVE: silent when high NVLink traffic coincides "
          "with genuinely high compute utilization",
          len(fired) == 0, f"fired {len(fired)} times -- FALSE POSITIVE")


def test_message_discloses_collective_communication_overlap():
    """The core honesty check: the message must not claim a confirmed
    covert channel when normal all-reduce/all-gather produces an
    identical signature."""
    d = NVLinkContentionDetector(baseline_min_samples=30, require_consecutive=5,
                                  delta_threshold_kbs=1000.0)
    for _ in range(30):
        d.update(row(**{'utilization.gpu': 5}, nvlink_tx_kbs=100, nvlink_rx_kbs=100))
    alerts = [d.update(row(**{'utilization.gpu': 5},
                            nvlink_tx_kbs=5000, nvlink_rx_kbs=5000))
              for _ in range(6)]
    fired = [a for a in alerts if a]
    check("NVLINK: message discloses the collective-communication "
          "overlap honestly, doesn't overclaim a confirmed attack",
          fired and 'all-reduce' in fired[0]['message']
          and 'unconfirmed' in fired[0]['message'],
          f"got {fired[0]['message'] if fired else 'no alert'}")


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
