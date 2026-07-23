# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
tests/test_predictive_failure_na_safety.py

Tests that FanWearDetector, CapacitorAgingDetector, and
PackageCrackingDetector no longer crash on None (the real value _f()
returns for nvidia-smi's '[N/A]' string) -- all three previously used
raw float(row.get(key, 0)), which would raise TypeError the instant
agent/telemetry.py stops silently coercing N/A to 0.0. This is the
last of the 16 pipeline detectors confirmed unsafe for that change;
pcie_health.py and attestation.py were confirmed already safe by
inspection (neither parses row-level float fields the same way).

Run: python tests/test_predictive_failure_na_safety.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.predictive_failure import (
    FanWearDetector, CapacitorAgingDetector, PackageCrackingDetector,
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


def row(**kw):
    base = {'index': 0, 'iso_timestamp': '2026-07-21T00:00:00'}
    base.update(kw)
    return base


def test_fan_wear_survives_none_temp():
    d = FanWearDetector(window=5)
    try:
        for _ in range(10):
            d.update(row(**{'temperature.gpu': None, 'utilization.gpu': 80}))
        check("FanWearDetector: survives None temperature.gpu without crashing", True)
    except TypeError as e:
        check("FanWearDetector: survives None temperature.gpu without crashing",
              False, f"crashed: {e}")


def test_fan_wear_survives_none_util():
    d = FanWearDetector(window=5)
    try:
        for _ in range(10):
            d.update(row(**{'temperature.gpu': 85, 'utilization.gpu': None}))
        check("FanWearDetector: survives None utilization.gpu without crashing", True)
    except TypeError as e:
        check("FanWearDetector: survives None utilization.gpu without crashing",
              False, f"crashed: {e}")


def test_capacitor_aging_survives_none_power():
    d = CapacitorAgingDetector(window=5)
    try:
        for _ in range(10):
            d.update(row(**{'power.draw': None, 'utilization.gpu': 60}))
        check("CapacitorAgingDetector: survives None power.draw without crashing", True)
    except TypeError as e:
        check("CapacitorAgingDetector: survives None power.draw without crashing",
              False, f"crashed: {e}")


def test_package_cracking_survives_none_temp():
    d = PackageCrackingDetector(window=5)
    try:
        for _ in range(10):
            d.update(row(**{'temperature.gpu': None, 'utilization.gpu': 70}))
        check("PackageCrackingDetector: survives None temperature.gpu without crashing", True)
    except TypeError as e:
        check("PackageCrackingDetector: survives None temperature.gpu without crashing",
              False, f"crashed: {e}")


def test_all_three_return_none_not_crash_on_missing_key_entirely():
    """A row missing the key entirely (not even present) must also be
    handled -- _f()'s row.get(key) returns None the same as an
    explicit None value."""
    d1, d2, d3 = FanWearDetector(window=5), CapacitorAgingDetector(window=5), PackageCrackingDetector(window=5)
    try:
        for _ in range(10):
            bare_row = row()  # no temperature.gpu, power.draw, or utilization.gpu at all
            d1.update(bare_row)
            d2.update(bare_row)
            d3.update(bare_row)
        check("all 3 detectors: survive a row missing the keys entirely", True)
    except TypeError as e:
        check("all 3 detectors: survive a row missing the keys entirely",
              False, f"crashed: {e}")


# ---------------------------------------------------------------------
# Regression: real numeric behavior must be unchanged
# ---------------------------------------------------------------------

def test_fan_wear_positive_control_unchanged():
    d = FanWearDetector(window=20)
    fired = False
    for _ in range(20):
        r = d.update(row(**{'temperature.gpu': 85, 'utilization.gpu': 90}))
        if r:
            fired = True
    check("FanWearDetector: still fires correctly on real sustained "
          "high temp + high util (regression)", fired)


def test_capacitor_aging_positive_control_unchanged():
    d = CapacitorAgingDetector(window=60)
    fired = False
    for i in range(60):
        power = 300 if i % 2 == 0 else 200  # 50 pts of >40% util, big ripple
        r = d.update(row(**{'power.draw': power, 'utilization.gpu': 60}))
        if r:
            fired = True
    check("CapacitorAgingDetector: still fires correctly on real "
          "sustained power ripple (regression)", fired)


def test_package_cracking_positive_control_unchanged():
    d = PackageCrackingDetector(window=30)
    fired = False
    for i in range(30):
        temp = 70 if i < 15 else 85  # >8C delta among high-util samples
        r = d.update(row(**{'temperature.gpu': temp, 'utilization.gpu': 70}))
        if r:
            fired = True
    check("PackageCrackingDetector: still fires correctly on real "
          "temp delta under load (regression)", fired)


def test_fan_wear_negative_control_unchanged():
    d = FanWearDetector(window=20)
    fired = False
    for _ in range(20):
        r = d.update(row(**{'temperature.gpu': 60, 'utilization.gpu': 20}))
        if r:
            fired = True
    check("FanWearDetector: stays silent on normal cool/idle operation "
          "(regression, no false positive)", not fired)


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
