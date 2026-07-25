"""
tests/test_telemetry_honesty.py

Tests for detection/telemetry_honesty.py: PStateHonestyDetector and
PCIeBandwidthMismatchDetector. Neither has been run against real
hardware -- see the module's own docstring. These tests confirm the
logic behaves correctly on synthetic data only.

Run: python tests/test_telemetry_honesty.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.telemetry_honesty import PStateHonestyDetector, PCIeBandwidthMismatchDetector

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
    base = {'index': 0, 'iso_timestamp': '2026-07-25T00:00:00'}
    base.update(kw)
    return base


def test_pstate_positive_p8_with_high_power():
    d = PStateHonestyDetector(require_consecutive=5)
    result = None
    for _ in range(6):
        result = d.update(row(**{'pstate': 'P8', 'power.draw': 80})) or result
    check("PSTATE POSITIVE: fires when P8 reported with power above ceiling",
          result is not None and result['type'] == 'PSTATE_POWER_MISMATCH',
          f"got {result}")


def test_pstate_negative_p8_with_low_power():
    d = PStateHonestyDetector(require_consecutive=5)
    results = []
    for _ in range(6):
        results.append(d.update(row(**{'pstate': 'P8', 'power.draw': 15})))
    fired = [r for r in results if r]
    check("PSTATE NEGATIVE: silent when P8 power draw is genuinely low",
          len(fired) == 0, f"fired {len(fired)} times")


def test_pstate_negative_p0_with_high_power():
    d = PStateHonestyDetector(require_consecutive=5)
    results = []
    for _ in range(6):
        results.append(d.update(row(**{'pstate': 'P0', 'power.draw': 300})))
    fired = [r for r in results if r]
    check("PSTATE NEGATIVE: silent on P0 with high power (expected, not a mismatch)",
          len(fired) == 0, f"fired {len(fired)} times")


def test_pstate_none_when_pstate_missing():
    d = PStateHonestyDetector()
    result = d.update(row(**{'power.draw': 80}))
    check("PSTATE: returns None when pstate field is absent",
          result is None, f"got {result}")


def test_pstate_none_when_power_missing():
    d = PStateHonestyDetector()
    result = d.update(row(**{'pstate': 'P8'}))
    check("PSTATE: returns None when power.draw field is absent",
          result is None, f"got {result}")


def test_pstate_survives_na_power():
    d = PStateHonestyDetector()
    try:
        result = d.update(row(**{'pstate': 'P8', 'power.draw': '[N/A]'}))
        check("PSTATE: survives N/A power.draw without crashing (returns None)",
              result is None, f"got {result}")
    except Exception as e:
        check("PSTATE: survives N/A power.draw without crashing",
              False, f"crashed: {e}")


def test_pcie_positive_high_bandwidth_low_util():
    d = PCIeBandwidthMismatchDetector(require_consecutive=5)
    result = None
    for _ in range(6):
        result = d.update(row(**{'pcie.bandwidth.util_pct': 75, 'utilization.gpu': 2})) or result
    check("PCIE POSITIVE: fires on high PCIe bandwidth with near-zero compute util",
          result is not None and result['type'] == 'PCIE_BANDWIDTH_MISMATCH',
          f"got {result}")


def test_pcie_negative_high_bandwidth_high_util():
    d = PCIeBandwidthMismatchDetector(require_consecutive=5)
    results = []
    for _ in range(6):
        results.append(d.update(row(**{'pcie.bandwidth.util_pct': 75, 'utilization.gpu': 90})))
    fired = [r for r in results if r]
    check("PCIE NEGATIVE: silent on high bandwidth WITH high compute utilization",
          len(fired) == 0, f"fired {len(fired)} times")


def test_pcie_negative_low_bandwidth_low_util():
    d = PCIeBandwidthMismatchDetector(require_consecutive=5)
    results = []
    for _ in range(6):
        results.append(d.update(row(**{'pcie.bandwidth.util_pct': 5, 'utilization.gpu': 2})))
    fired = [r for r in results if r]
    check("PCIE NEGATIVE: silent on genuinely idle GPU (low bandwidth, low util)",
          len(fired) == 0, f"fired {len(fired)} times")


def test_pcie_none_when_fields_missing():
    d = PCIeBandwidthMismatchDetector()
    result = d.update(row(**{'utilization.gpu': 2}))
    check("PCIE: returns None when pcie.bandwidth.util_pct is absent",
          result is None, f"got {result}")


def test_pcie_survives_na_fields():
    d = PCIeBandwidthMismatchDetector()
    try:
        result = d.update(row(**{'pcie.bandwidth.util_pct': '[N/A]', 'utilization.gpu': 2}))
        check("PCIE: survives N/A pcie.bandwidth.util_pct without crashing",
              result is None, f"got {result}")
    except Exception as e:
        check("PCIE: survives N/A pcie.bandwidth.util_pct without crashing",
              False, f"crashed: {e}")


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
