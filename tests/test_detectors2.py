#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_detectors2.py

Tests for two new detectors added from 2025-2026 research:

  NVIDIAContainerToolkitCVEChecker  -- CVE-2025-23266 version check
  ContextSwitchTimingDetector        -- Leaky DNN / micro-arch covert channel

Run: python3 tests/test_detectors2.py
"""
import sys
import os
from unittest.mock import patch
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.hardware_attacks import (
    NVIDIAContainerToolkitCVEChecker,
    ContextSwitchTimingDetector,
)

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    if cond:
        PASSED.append(name); print(f"[PASS] {name}")
    else:
        FAILED.append(name); print(f"[FAIL] {name} {detail}")


def row(i, util, clock, idx=0):
    ts = (datetime(2026, 8, 1) + timedelta(seconds=i)).isoformat()
    return {'index': idx, 'iso_timestamp': ts,
            'utilization.gpu': util, 'clocks.sm': clock}


# ---- CVE checker ----

def test_cve_not_installed():
    d = NVIDIAContainerToolkitCVEChecker()
    with patch.object(d, '_get_installed_version', return_value=None):
        check("CVE: returns None when toolkit not installed",
              d.check() is None)


def test_cve_patched():
    d = NVIDIAContainerToolkitCVEChecker()
    with patch.object(d, '_get_installed_version', return_value=(1, 17, 4)):
        check("CVE: returns None when version is patched (1.17.4)",
              d.check() is None)


def test_cve_newer_patched():
    d = NVIDIAContainerToolkitCVEChecker()
    with patch.object(d, '_get_installed_version', return_value=(1, 18, 0)):
        check("CVE: returns None when version is newer than fix",
              d.check() is None)


def test_cve_vulnerable():
    d = NVIDIAContainerToolkitCVEChecker()
    with patch.object(d, '_get_installed_version', return_value=(1, 17, 3)):
        r = d.check()
        check("CVE POSITIVE: fires on vulnerable version (1.17.3)",
              r is not None and r['type'] == 'CONTAINER_TOOLKIT_CVE'
              and r['severity'] == 'CRITICAL', f"got {r}")
        if r:
            check("CVE: alert names the CVE ID",
                  'CVE-2025-23266' in r['message'])
            check("CVE: alert names the fixed version",
                  '1.17.4' in r['message'])


def test_cve_fires_once():
    d = NVIDIAContainerToolkitCVEChecker()
    with patch.object(d, '_get_installed_version', return_value=(1, 17, 3)):
        r1 = d.check()
        r2 = d.update({})
        check("CVE: fires once then stays silent",
              r1 is not None and r2 is None, f"r1={r1} r2={r2}")


def test_cve_update_compatible():
    d = NVIDIAContainerToolkitCVEChecker()
    with patch.object(d, '_get_installed_version', return_value=(1, 16, 0)):
        r = d.update({'index': 0})
        check("CVE: update(row) interface fires correctly",
              r is not None and r['severity'] == 'CRITICAL')


# ---- Context switch timing ----

def test_ctx_negative_stable_idle_clock():
    d = ContextSwitchTimingDetector(baseline_min_samples=15,
                                     window_samples=10,
                                     require_consecutive=3)
    fired = [a for a in (d.update(row(i, 0, 1980 + (i % 3)))
                          for i in range(60)) if a]
    check("CTX NEGATIVE: silent on stable idle SM clock",
          len(fired) == 0, f"fired {len(fired)}x -- FALSE POSITIVE")


def test_ctx_negative_busy_with_variance():
    d = ContextSwitchTimingDetector(baseline_min_samples=15,
                                     window_samples=10,
                                     require_consecutive=3)
    for i in range(20):
        d.update(row(i, 0, 1980))
    fired = [a for a in (d.update(row(i, 90, 1980 + (i % 200)))
                          for i in range(20, 60)) if a]
    check("CTX NEGATIVE: silent when GPU is genuinely busy",
          len(fired) == 0, f"fired {len(fired)}x -- FALSE POSITIVE")


def test_ctx_positive_high_variance_at_idle():
    d = ContextSwitchTimingDetector(baseline_min_samples=15,
                                     window_samples=10,
                                     require_consecutive=3,
                                     clock_variance_threshold=50.0)
    for i in range(25):
        d.update(row(i, 0, 1980))
    fired = [a for a in (d.update(row(i, 2, 1980 + (i % 200) - 100))
                          for i in range(25, 60)) if a]
    check("CTX POSITIVE: fires on high SM clock variance at idle",
          bool(fired) and fired[0]['type'] == 'CONTEXT_SWITCH_CLOCK_VARIANCE',
          f"got {len(fired)} fired")
    if fired:
        check("CTX: severity is INFO not CRITICAL",
              fired[0]['severity'] == 'INFO')
        check("CTX: message discloses DVFS as alternative cause",
              'DVFS' in fired[0]['message'])
        check("CTX: message states no model weights recovered",
              'no model weights' in fired[0]['message'])


def test_ctx_missing_clock_field():
    d = ContextSwitchTimingDetector()
    r = d.update({'index': 0, 'utilization.gpu': 0})
    check("CTX: returns None when clocks.sm absent", r is None)


if __name__ == '__main__':
    for _name, _fn in sorted(globals().items()):
        if _name.startswith('test_'):
            try:
                _fn()
            except Exception as e:
                check(_name, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
