# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_nvlink_contention_detector.py

Tests for NVLinkContentionDetector -- learned baseline, edge-triggered,
including the honest negative control matching its own disclosed
discrimination gap (normal collective-communication bursts must not
fire if they're within the learned baseline's normal variance).

REWRITTEN after a critical fix: NVLinkContentionDetector previously
compared raw cumulative nvidia-smi counters directly, which measured
elapsed time rather than traffic (a real B200 test produced a 61.5
billion KB/s reading from this bug). The detector now computes a real
per-second rate from consecutive samples' iso_timestamp before any
baseline/threshold logic runs. These tests now feed a climbing
cumulative counter with real timestamps, matching genuine nvidia-smi
behavior, instead of the old constant/plateau values that only worked
against the buggy cumulative-comparison logic.

Run: python tests/test_nvlink_contention_detector.py
"""

import sys
import os
from datetime import datetime, timedelta

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


def row(ts, **kw):
    base = {'index': 0, 'iso_timestamp': ts.isoformat(),
            'nvlink_available': True}
    base.update(kw)
    return base


def climbing_counter_rows(n, start_kbs, per_sample_kbs, util, start_ts=None):
    """Simulates n real nvidia-smi samples, one real second apart, where
    the cumulative counter climbs by per_sample_kbs each step -- this is
    what a steady real per-second_kbs rate actually looks like on the wire."""
    ts = start_ts or datetime(2026, 7, 30, 0, 0, 0)
    rows = []
    c = start_kbs
    for i in range(n):
        rows.append(row(ts, **{'utilization.gpu': util},
                         nvlink_tx_kbs=c / 2.0, nvlink_rx_kbs=c / 2.0))
        c += per_sample_kbs
        ts += timedelta(seconds=1)
    return rows


def test_silent_when_nvlink_unavailable():
    """Most GPUs (L40S, RTX-series, T4, most single-GPU rentals) have
    no NVLink hardware at all -- must stay silent, not error or
    fabricate a reading."""
    d = NVLinkContentionDetector(baseline_min_samples=5, require_consecutive=2)
    ts = datetime(2026, 7, 30, 0, 0, 0)
    alerts = []
    for i in range(10):
        alerts.append(d.update(row(ts + timedelta(seconds=i),
                                    nvlink_available=False,
                                    **{'utilization.gpu': 5})))
    fired = [a for a in alerts if a]
    check("NVLINK: silent when nvlink_available is False (no hardware)",
          len(fired) == 0, f"fired {len(fired)} times")


def test_silent_without_real_timestamps():
    """No iso_timestamp means no rate can be computed -- must fail
    closed, not fall back to guessing."""
    d = NVLinkContentionDetector(baseline_min_samples=3, require_consecutive=1,
                                  delta_threshold_kbs=50.0)
    alerts = []
    for _ in range(6):
        r = {'index': 0, 'nvlink_available': True, 'utilization.gpu': 5,
             'nvlink_tx_kbs': 1000, 'nvlink_rx_kbs': 1000}
        alerts.append(d.update(r))
    fired = [a for a in alerts if a]
    check("NVLINK: fails closed with no iso_timestamp on the row",
          len(fired) == 0, f"fired {len(fired)} times")


def test_negative_stable_low_rate():
    """Baseline learned at a stable low real per-second rate -- small
    natural variance around it must not fire."""
    d = NVLinkContentionDetector(baseline_min_samples=8, require_consecutive=3,
                                  delta_threshold_kbs=100.0)
    rows = climbing_counter_rows(8, start_kbs=1000, per_sample_kbs=200, util=5)
    for r in rows:
        d.update(r)
    ts = rows[-1]['iso_timestamp']
    last_ts = datetime.fromisoformat(ts)
    c = 1000 + 200 * 8
    alerts = []
    for i in range(6):
        last_ts += timedelta(seconds=1)
        variance = 200 + (i % 3) * 15
        alerts.append(d.update(row(last_ts, **{'utilization.gpu': 5},
                                    nvlink_tx_kbs=c / 2.0, nvlink_rx_kbs=c / 2.0)))
        c += variance
    fired = [a for a in alerts if a]
    check("NVLINK NEGATIVE: silent on small normal rate variance "
          "around the learned baseline",
          len(fired) == 0, f"fired {len(fired)} times -- FALSE POSITIVE")


def test_positive_sustained_elevated_rate_at_low_util():
    d = NVLinkContentionDetector(baseline_min_samples=8, require_consecutive=3,
                                  delta_threshold_kbs=100.0)
    rows = climbing_counter_rows(8, start_kbs=1000, per_sample_kbs=200, util=5)
    for r in rows:
        d.update(r)
    last_ts = datetime.fromisoformat(rows[-1]['iso_timestamp'])
    c = 1000 + 200 * 8
    alerts = []
    for _ in range(6):
        last_ts += timedelta(seconds=1)
        alerts.append(d.update(row(last_ts, **{'utilization.gpu': 5},
                                    nvlink_tx_kbs=c / 2.0, nvlink_rx_kbs=c / 2.0)))
        c += 5000
    fired = [a for a in alerts if a]
    check("NVLINK POSITIVE: fires on sustained elevated real rate "
          "at low compute utilization",
          len(fired) >= 1 and fired[0]['type'] == 'NVLINK_CONTENTION',
          f"got {len(fired)} fired")
    if fired:
        check("NVLINK POSITIVE: alert reports a physically sane rate, "
              "not raw counter drift",
              fired[0]['nvlink_total_kbs'] < 1_000_000,
              f"got {fired[0]['nvlink_total_kbs']} KB/s -- looks like the old bug")


def test_negative_silent_when_util_is_high():
    """High compute utilization alongside NVLink traffic is exactly the
    normal, expected multi-GPU compute pattern -- must not fire."""
    d = NVLinkContentionDetector(baseline_min_samples=8, require_consecutive=3,
                                  delta_threshold_kbs=100.0)
    rows = climbing_counter_rows(8, start_kbs=1000, per_sample_kbs=200, util=5)
    for r in rows:
        d.update(r)
    last_ts = datetime.fromisoformat(rows[-1]['iso_timestamp'])
    c = 1000 + 200 * 8
    alerts = []
    for _ in range(6):
        last_ts += timedelta(seconds=1)
        alerts.append(d.update(row(last_ts, **{'utilization.gpu': 80},
                                    nvlink_tx_kbs=c / 2.0, nvlink_rx_kbs=c / 2.0)))
        c += 5000
    fired = [a for a in alerts if a]
    check("NVLINK NEGATIVE: silent when high NVLink rate coincides "
          "with genuinely high compute utilization",
          len(fired) == 0, f"fired {len(fired)} times -- FALSE POSITIVE")


def test_message_discloses_collective_communication_overlap():
    """The core honesty check: the message must not claim a confirmed
    covert channel when normal all-reduce/all-gather produces an
    identical signature."""
    d = NVLinkContentionDetector(baseline_min_samples=8, require_consecutive=3,
                                  delta_threshold_kbs=100.0)
    rows = climbing_counter_rows(8, start_kbs=1000, per_sample_kbs=200, util=5)
    for r in rows:
        d.update(r)
    last_ts = datetime.fromisoformat(rows[-1]['iso_timestamp'])
    c = 1000 + 200 * 8
    alerts = []
    for _ in range(6):
        last_ts += timedelta(seconds=1)
        alerts.append(d.update(row(last_ts, **{'utilization.gpu': 5},
                                    nvlink_tx_kbs=c / 2.0, nvlink_rx_kbs=c / 2.0)))
        c += 5000
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
