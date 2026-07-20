"""
tests/test_memory_attacks_remaining_fixes.py

Tests for the 2 remaining fixed detectors in memory_attacks.py:
CacheSideChannelDetector, MIGPartitionDesyncDetector. Does NOT re-test
SequentialVRAMReadDetector -- already covered by
tests/test_hardware_memory_fixes.py.

Run: python tests/test_memory_attacks_remaining_fixes.py
"""

import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.memory_attacks import CacheSideChannelDetector, MIGPartitionDesyncDetector

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
    base = {'index': 0, 'iso_timestamp': '2026-07-19T00:00:00'}
    base.update(kw)
    return base


def fake_proc(stdout=""):
    class R:
        pass
    r = R()
    r.stdout, r.returncode = stdout, 0
    return r


def test_cache_sc_positive_edge_triggered():
    d = CacheSideChannelDetector(window=50, require_consecutive=3)
    for _ in range(50):
        d.update(row(**{'utilization.gpu': 5, 'utilization.memory': 60}))
    alerts = [d.update(row(**{'utilization.gpu': 5, 'utilization.memory': 60}))
              for _ in range(4)]
    fired = [a for a in alerts if a]
    check("CACHE_SC POSITIVE: fires on sustained high mem-spike ratio at low compute",
          len(fired) >= 1 and fired[0]['type'] == 'CACHE_SIDE_CHANNEL',
          f"got {len(fired)} fired")


def test_cache_sc_negative_normal_load():
    d = CacheSideChannelDetector(window=50, require_consecutive=3)
    alerts = []
    for _ in range(60):
        alerts.append(d.update(row(**{'utilization.gpu': 70, 'utilization.memory': 60})))
    fired = [a for a in alerts if a]
    check("CACHE_SC NEGATIVE: silent when GPU compute is genuinely active",
          len(fired) == 0, f"fired {len(fired)} times")


def test_cache_sc_notes_overlap_in_message():
    d = CacheSideChannelDetector(window=50, require_consecutive=3)
    for _ in range(50):
        d.update(row(**{'utilization.gpu': 5, 'utilization.memory': 60}))
    alerts = [d.update(row(**{'utilization.gpu': 5, 'utilization.memory': 60}))
              for _ in range(4)]
    fired = [a for a in alerts if a]
    check("CACHE_SC: message notes overlap with DMAAttackDetector honestly",
          fired and 'DMAAttackDetector' in fired[0]['message'],
          f"got {fired[0]['message'] if fired else 'none'}")


def test_mig_desync_negative_normal_idle_baseline():
    """The exact bug: a fixed util_mem>40 threshold with no baseline.
    Confirm a GPU whose NORMAL idle mem-util floor is above 40 doesn't
    false-positive once learned."""
    with patch('subprocess.run', return_value=fake_proc("No devices found\n")):
        d = MIGPartitionDesyncDetector(baseline_min_samples=30, require_consecutive=3)
        for _ in range(30):
            d.update(row(**{'utilization.gpu': 0, 'utilization.memory': 55}))
        alerts = [d.update(row(**{'utilization.gpu': 0, 'utilization.memory': 55}))
                  for _ in range(5)]
    fired = [a for a in alerts if a]
    check("MIG_DESYNC NEGATIVE: silent once a 55% idle mem-util floor is "
          "learned as this GPU's own normal state (would have "
          "false-positived against the old fixed 40% threshold)",
          len(fired) == 0, f"fired {len(fired)} times")


def test_mig_desync_positive_genuine_elevation():
    with patch('subprocess.run', return_value=fake_proc("No devices found\n")):
        d = MIGPartitionDesyncDetector(baseline_min_samples=30, require_consecutive=3)
        for _ in range(30):
            d.update(row(**{'utilization.gpu': 0, 'utilization.memory': 10}))
        alerts = [d.update(row(**{'utilization.gpu': 0, 'utilization.memory': 50}))
                  for _ in range(4)]
    fired = [a for a in alerts if a]
    check("MIG_DESYNC POSITIVE: fires on genuine elevation above learned floor",
          len(fired) >= 1 and fired[0]['type'] == 'MIG_PARTITION_DESYNC',
          f"got {len(fired)} fired")


def test_mig_desync_notes_when_mig_not_configured():
    with patch('subprocess.run', return_value=fake_proc("No devices found\n")):
        d = MIGPartitionDesyncDetector(baseline_min_samples=30, require_consecutive=3)
        for _ in range(30):
            d.update(row(**{'utilization.gpu': 0, 'utilization.memory': 10}))
        alerts = [d.update(row(**{'utilization.gpu': 0, 'utilization.memory': 50}))
                  for _ in range(4)]
    fired = [a for a in alerts if a]
    check("MIG_DESYNC: notes when MIG doesn't appear configured on this "
          "GPU, so the cross-partition framing may not apply",
          fired and fired[0]['mig_configured'] is False
          and 'no MIG partitions appear configured' in fired[0]['message'],
          f"got {fired[0] if fired else 'none'}")


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
