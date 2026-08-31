#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_detectors4.py

Tests for two detectors added from August 2026 confidential-computing
research:

  ConfidentialComputingModeDetector      -- CC-DevTools downgrade
  MIGCachePartitionSideChannelDetector   -- "Behind Bars" MIG precondition

Run: python3 tests/test_detectors4.py
"""
import sys, os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from detection.hardware_attacks import (
    ConfidentialComputingModeDetector,
    MIGCachePartitionSideChannelDetector,
)

PASSED, FAILED = [], []

def check(name, cond, detail=""):
    if cond:
        PASSED.append(name); print(f"[PASS] {name}")
    else:
        FAILED.append(name); print(f"[FAIL] {name} {detail}")

def ts(i):
    return (datetime(2026, 8, 1) + timedelta(seconds=i)).isoformat()


# ---- CC mode ----

def test_cc_on_is_silent():
    d = ConfidentialComputingModeDetector(require_consecutive=2)
    fired = [d.update({'index': 0, 'iso_timestamp': ts(i), 'cc_mode': 'On'})
             for i in range(5)]
    check("CC NEGATIVE: silent when mode is On",
          all(f is None for f in fired))


def test_cc_off_is_silent():
    d = ConfidentialComputingModeDetector(require_consecutive=2)
    fired = [d.update({'index': 0, 'iso_timestamp': ts(i), 'cc_mode': 'Off'})
             for i in range(5)]
    check("CC NEGATIVE: silent when mode is Off",
          all(f is None for f in fired))


def test_cc_absent_is_silent():
    d = ConfidentialComputingModeDetector()
    check("CC NEGATIVE: silent when no CC field present (not applicable)",
          d.update({'index': 0, 'iso_timestamp': ts(0)}) is None)


def test_cc_devtools_fires():
    d = ConfidentialComputingModeDetector(require_consecutive=2)
    r1 = d.update({'index': 0, 'iso_timestamp': ts(0), 'cc_mode': 'DevTools'})
    r2 = d.update({'index': 0, 'iso_timestamp': ts(1), 'cc_mode': 'DevTools'})
    check("CC POSITIVE: fires on DevTools after require_consecutive",
          r1 is None and r2 is not None
          and r2['type'] == 'CC_MODE_DOWNGRADED_DEVTOOLS', f"got {r2}")
    if r2:
        check("CC: severity WARNING not CRITICAL (DevTools is legit mode)",
              r2['severity'] == 'WARNING')
        check("CC: message explains the downgrade",
              'RE-ENABLES performance counters' in r2['message'])
        check("CC: message discloses profiling false-positive",
              'profiling' in r2['message'])


def test_cc_alt_field_name():
    d = ConfidentialComputingModeDetector(require_consecutive=1)
    r = d.update({'index': 0, 'iso_timestamp': ts(0),
                  'conf_compute_mode': 'cc-devtools'})
    check("CC: reads alternate field name conf_compute_mode",
          r is not None and r['type'] == 'CC_MODE_DOWNGRADED_DEVTOOLS')


# ---- MIG ----

def mig_row(i, mig='enabled', instances=4, util=10, mem=60):
    return {'index': 0, 'iso_timestamp': ts(i), 'mig_mode': mig,
            'mig_active_instances': instances,
            'utilization.gpu': util, 'utilization.memory': mem}


def test_mig_disabled_silent():
    d = MIGCachePartitionSideChannelDetector(require_consecutive=2)
    fired = [d.update(mig_row(i, mig='disabled')) for i in range(6)]
    check("MIG NEGATIVE: silent when MIG disabled",
          all(f is None for f in fired))


def test_mig_single_instance_silent():
    d = MIGCachePartitionSideChannelDetector(require_consecutive=2)
    fired = [d.update(mig_row(i, instances=1)) for i in range(6)]
    check("MIG NEGATIVE: silent with fewer than 2 instances",
          all(f is None for f in fired))


def test_mig_low_interference_silent():
    d = MIGCachePartitionSideChannelDetector(require_consecutive=2,
                                             l2_interference_threshold=25.0)
    fired = [d.update(mig_row(i, util=50, mem=60)) for i in range(6)]
    check("MIG NEGATIVE: silent when mem-bw tracks compute (delta<threshold)",
          all(f is None for f in fired))


def test_mig_interference_fires():
    d = MIGCachePartitionSideChannelDetector(require_consecutive=2,
                                             l2_interference_threshold=25.0)
    fired = [d.update(mig_row(i, util=5, mem=70)) for i in range(6)]
    hit = [f for f in fired if f]
    check("MIG POSITIVE: fires on high mem-bw at low compute, MIG active",
          bool(hit) and hit[0]['type'] == 'MIG_CROSS_PARTITION_INTERFERENCE',
          f"got {len(hit)}")
    if hit:
        check("MIG: severity INFO (precondition flag, not attack proof)",
              hit[0]['severity'] == 'INFO')
        check("MIG: message states it is not attack proof",
              'not attack proof' in hit[0]['message'])
        check("MIG: message flags research-stage / needs MIG pod",
              'Research-stage' in hit[0]['message'])


def test_mig_missing_fields_silent():
    d = MIGCachePartitionSideChannelDetector()
    r = d.update({'index': 0, 'iso_timestamp': ts(0), 'mig_mode': 'enabled',
                  'mig_active_instances': 4})
    check("MIG: silent when util/mem fields absent (fail closed)",
          r is None)


if __name__ == '__main__':
    for _n, _f in sorted(globals().items()):
        if _n.startswith('test_'):
            try:
                _f()
            except Exception as e:
                check(_n, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    for f in FAILED:
        print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
