# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_hardware_attacks_remaining_fixes.py

Tests for the 3 remaining fixed detectors in hardware_attacks.py:
ClockGlitchDetector, VoltageGlitchDetector, LaserInjectionDetector.
Does NOT re-test DMAAttackDetector -- already covered by
tests/test_hardware_memory_fixes.py.

Run: python tests/test_hardware_attacks_remaining_fixes.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.hardware_attacks import (
    ClockGlitchDetector, VoltageGlitchDetector, LaserInjectionDetector,
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
    base = {'index': 0, 'iso_timestamp': '2026-07-19T00:00:00'}
    base.update(kw)
    return base


def test_clock_glitch_negative_normal_dvfs_variance():
    """The exact bug: normal boost-clock variance under sustained load
    must NOT fire, since it compared a window's own mean to its own min."""
    d = ClockGlitchDetector(baseline_min_samples=30, require_consecutive=3)
    for _ in range(30):
        d.update(row(**{'clocks.sm': 1980, 'utilization.gpu': 80}))
    alerts = []
    for i in range(10):
        clock = 1980 - (i % 3) * 40
        alerts.append(d.update(row(**{'clocks.sm': clock, 'utilization.gpu': 80})))
    fired = [a for a in alerts if a]
    check("CLOCK_GLITCH NEGATIVE: silent on normal small DVFS variance",
          len(fired) == 0, f"fired {len(fired)} times -- FALSE POSITIVE")


def test_clock_glitch_positive_sustained_real_drop():
    d = ClockGlitchDetector(baseline_min_samples=30, require_consecutive=3)
    for _ in range(30):
        d.update(row(**{'clocks.sm': 1980, 'utilization.gpu': 80}))
    alerts = [d.update(row(**{'clocks.sm': 1500, 'utilization.gpu': 80}))
              for _ in range(6)]
    fired = [a for a in alerts if a]
    check("CLOCK_GLITCH POSITIVE: fires on sustained large drop below baseline",
          len(fired) >= 1 and fired[0]['type'] == 'CLOCK_GLITCH',
          f"got {len(fired)} fired")


def test_clock_glitch_message_states_cause_unconfirmed():
    d = ClockGlitchDetector(baseline_min_samples=30, require_consecutive=3)
    for _ in range(30):
        d.update(row(**{'clocks.sm': 1980, 'utilization.gpu': 80}))
    alerts = [d.update(row(**{'clocks.sm': 1500, 'utilization.gpu': 80}))
              for _ in range(6)]
    fired = [a for a in alerts if a]
    check("CLOCK_GLITCH: message states cause unconfirmed, doesn't claim "
          "'injection' as established fact",
          fired and 'unconfirmed' in fired[0]['message'],
          f"got {fired[0]['message'] if fired else 'no alert'}")


def test_voltage_glitch_negative_normal_power_capping():
    """Normal power-limit throttling under sustained load must not fire."""
    d = VoltageGlitchDetector(baseline_min_samples=30, require_consecutive=3)
    for _ in range(30):
        d.update(row(**{'power.draw': 700, 'utilization.gpu': 90}))
    alerts = []
    for i in range(10):
        power = 700 - (i % 3) * 10
        alerts.append(d.update(row(**{'power.draw': power, 'utilization.gpu': 90})))
    fired = [a for a in alerts if a]
    check("VOLTAGE_GLITCH NEGATIVE: silent on small normal power variance",
          len(fired) == 0, f"fired {len(fired)} times -- FALSE POSITIVE")


def test_voltage_glitch_positive_sustained_real_drop():
    d = VoltageGlitchDetector(baseline_min_samples=30, require_consecutive=3)
    for _ in range(30):
        d.update(row(**{'power.draw': 700, 'utilization.gpu': 90}))
    alerts = [d.update(row(**{'power.draw': 600, 'utilization.gpu': 90}))
              for _ in range(11)]
    fired = [a for a in alerts if a]
    check("VOLTAGE_GLITCH POSITIVE: fires on sustained large drop below baseline",
          len(fired) >= 1 and fired[0]['type'] == 'VOLTAGE_GLITCH',
          f"got {len(fired)} fired")


def test_voltage_glitch_negative_unstable_util():
    """If util itself is jumping around, this isn't a clean 'stable util,
    power dropped' signature -- must not fire."""
    d = VoltageGlitchDetector(baseline_min_samples=30, require_consecutive=3)
    for _ in range(30):
        d.update(row(**{'power.draw': 700, 'utilization.gpu': 90}))
    alerts = []
    for i in range(15):
        util = 90 if i % 2 == 0 else 40
        alerts.append(d.update(row(**{'power.draw': 600, 'utilization.gpu': util})))
    fired = [a for a in alerts if a]
    check("VOLTAGE_GLITCH NEGATIVE: silent when util is unstable, even "
          "with a power drop", len(fired) == 0, f"fired {len(fired)} times")


def test_laser_severity_downgraded_to_info():
    d = LaserInjectionDetector(require_consecutive=1)
    alert = None
    for t in [30, 32, 35, 40, 46]:
        alert = d.update(row(**{'temperature.gpu': t})) or alert
    check("LASER: severity is INFO, not EMERGENCY, since cause cannot be "
          "confirmed from software telemetry",
          alert is not None and alert['severity'] == 'INFO',
          f"got {alert}")


def test_laser_message_disclaims_physical_detection_claim():
    d = LaserInjectionDetector(require_consecutive=1)
    alert = None
    for t in [30, 32, 35, 40, 46]:
        alert = d.update(row(**{'temperature.gpu': t})) or alert
    check("LASER: message explicitly states this cannot detect physical "
          "fault injection from software telemetry",
          alert is not None and 'cannot be detected' in alert['message'],
          f"got {alert['message'] if alert else 'no alert'}")


def test_laser_negative_no_transient():
    d = LaserInjectionDetector(require_consecutive=1)
    alerts = []
    for t in [40, 40.5, 41, 40.8, 41.2]:
        alerts.append(d.update(row(**{'temperature.gpu': t})))
    fired = [a for a in alerts if a]
    check("LASER NEGATIVE: silent on stable temperature, no transient",
          len(fired) == 0, f"fired {len(fired)} times")


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
