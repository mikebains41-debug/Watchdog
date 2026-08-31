#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_neutral_current.py

Tests NeutralCurrentHarmonicDetector logic against synthetic samples.
These prove the detector fires correctly on the harmonic-addition case
and stays silent on balanced linear load. They do NOT validate the
thresholds against a real facility -- no PDU has been queried.

Run: python3 tests/test_neutral_current.py
"""
import sys, os, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from detection.neutral_current_harmonic import (
    NeutralCurrentHarmonicDetector, ElectricalSample, NullPDUSource)

PASSED, FAILED = [], []

def check(name, cond, detail=""):
    if cond:
        PASSED.append(name); print(f"[PASS] {name}")
    else:
        FAILED.append(name); print(f"[FAIL] {name} {detail}")


class FixedSource:
    def __init__(self, sample):
        self.sample = sample
    def read_sample(self):
        return self.sample


def s(pa, pb, pc, n, h3=None):
    return ElectricalSample(time.time(), pa, pb, pc, n, third_harmonic_pct=h3)


def test_balanced_linear_silent():
    d = NeutralCurrentHarmonicDetector(NullPDUSource(), require_consecutive=1)
    check("NEGATIVE: balanced linear load (5A neutral, 100A phases) silent",
          d.check() is None)


def test_no_load_silent():
    d = NeutralCurrentHarmonicDetector(FixedSource(s(0, 0, 0, 0)),
                                       require_consecutive=1)
    check("NEGATIVE: zero load returns None, no divide-by-zero",
          d.check() is None)


def test_neutral_warning_threshold():
    d = NeutralCurrentHarmonicDetector(FixedSource(s(100, 90, 80, 85)),
                                       require_consecutive=1)
    a = d.check()
    check("POSITIVE: neutral at 85% of phase fires WARNING",
          a is not None and a.severity == "WARNING", f"got {a}")


def test_neutral_critical_threshold():
    d = NeutralCurrentHarmonicDetector(FixedSource(s(100, 90, 80, 105)),
                                       require_consecutive=1)
    a = d.check()
    check("POSITIVE: neutral exceeding highest phase fires CRITICAL",
          a is not None and a.severity == "CRITICAL", f"got {a}")


def test_third_harmonic_critical():
    d = NeutralCurrentHarmonicDetector(FixedSource(s(100, 100, 100, 40, 35.0)),
                                       require_consecutive=1)
    a = d.check()
    check("POSITIVE: third-harmonic >=33% fires CRITICAL at moderate neutral",
          a is not None and a.severity == "CRITICAL"
          and "third-harmonic" in a.message, f"got {a}")


def test_debounce_requires_persistence():
    d = NeutralCurrentHarmonicDetector(FixedSource(s(100, 90, 80, 105)),
                                       require_consecutive=3)
    r1, r2, r3 = d.check(), d.check(), d.check()
    check("DEBOUNCE: fires only after require_consecutive persistent reads",
          r1 is None and r2 is None and r3 is not None,
          f"got {r1}, {r2}, {r3}")


def test_debounce_resets_on_clean():
    src = FixedSource(s(100, 90, 80, 105))
    d = NeutralCurrentHarmonicDetector(src, require_consecutive=3)
    d.check(); d.check()
    src.sample = s(100, 100, 100, 5)
    d.check()
    src.sample = s(100, 90, 80, 105)
    r1, r2 = d.check(), d.check()
    check("DEBOUNCE: a clean reading resets the counter",
          r1 is None and r2 is None, f"got {r1}, {r2}")


def test_message_states_electrical_remediation():
    d = NeutralCurrentHarmonicDetector(FixedSource(s(100, 90, 80, 105)),
                                       require_consecutive=1)
    a = d.check()
    check("HONESTY: message says remediation is electrical, not software",
          a is not None and "electrical" in a.message)


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_"):
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
