# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_na_masking_fix.py

Tests the core fix: parse_numeric_fields() now sets None on parse
failure (e.g. nvidia-smi's literal '[N/A]' string), not a fabricated
0.0. Also tests _safe_fmt(), the companion fix needed because the
periodic status print's row.get(key, 0) only supplies its default when
the KEY is missing, not when the value is an explicit None -- which is
now a real, reachable case instead of a theoretical one.

Run: python tests/test_na_masking_fix.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from agent.telemetry import parse_numeric_fields, _safe_fmt, NUMERIC_FIELDS

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def test_na_string_becomes_none_not_zero():
    row = {'power.draw': '[N/A]', 'utilization.gpu': '45'}
    result = parse_numeric_fields(row, fields=['power.draw', 'utilization.gpu'])
    check("'[N/A]' string becomes None, not a fabricated 0.0",
          result['power.draw'] is None, f"got {result['power.draw']!r}")
    check("a genuinely parseable field still parses correctly alongside it",
          result['utilization.gpu'] == 45.0, f"got {result['utilization.gpu']!r}")


def test_real_zero_is_preserved_as_zero_not_confused_with_na():
    """The whole point of this fix: a REAL 0 reading must stay 0.0,
    distinguishable from an N/A that also used to become 0.0."""
    row = {'utilization.gpu': '0'}
    result = parse_numeric_fields(row, fields=['utilization.gpu'])
    check("a genuine zero reading is preserved as 0.0, not confused "
          "with N/A (both used to collapse to the same 0.0 before "
          "this fix)",
          result['utilization.gpu'] == 0.0 and result['utilization.gpu'] is not None,
          f"got {result['utilization.gpu']!r}")


def test_missing_key_also_becomes_none():
    row = {}
    result = parse_numeric_fields(row, fields=['power.draw'])
    check("a field missing from the row entirely also becomes None, "
          "not a KeyError or a fabricated 0.0",
          result['power.draw'] is None, f"got {result['power.draw']!r}")


def test_all_real_query_fields_survive_na_without_crashing():
    """Every field in the real NUMERIC_FIELDS list, not just one."""
    row = {f: '[N/A]' for f in NUMERIC_FIELDS}
    try:
        result = parse_numeric_fields(row)
        check("all real NUMERIC_FIELDS survive '[N/A]' without crashing, "
              "every one becomes None",
              all(result[f] is None for f in NUMERIC_FIELDS),
              f"got {result}")
    except Exception as e:
        check("all real NUMERIC_FIELDS survive '[N/A]' without crashing",
              False, f"crashed: {e}")


def test_mixed_row_only_na_fields_become_none():
    """A realistic mixed row -- only the N/A field should be affected."""
    row = {'power.draw': '250.5', 'temperature.gpu': '[N/A]',
           'utilization.gpu': '80', 'memory.used': '4096'}
    result = parse_numeric_fields(
        row, fields=['power.draw', 'temperature.gpu', 'utilization.gpu', 'memory.used'])
    check("mixed row: real fields parse correctly",
          result['power.draw'] == 250.5 and result['utilization.gpu'] == 80.0
          and result['memory.used'] == 4096.0,
          f"got {result}")
    check("mixed row: only the actual N/A field becomes None",
          result['temperature.gpu'] is None, f"got {result}")


def test_safe_fmt_shows_na_for_none():
    check("_safe_fmt: None displays as 'N/A', doesn't crash",
          _safe_fmt(None) == 'N/A', f"got {_safe_fmt(None)!r}")


def test_safe_fmt_formats_real_numbers_normally():
    check("_safe_fmt: a real float formats exactly as before (.1f default)",
          _safe_fmt(250.567) == '250.6', f"got {_safe_fmt(250.567)!r}")
    check("_safe_fmt: custom format spec is respected",
          _safe_fmt(80.0, '.0f') == '80', f"got {_safe_fmt(80.0, '.0f')!r}")


def test_the_exact_crash_this_fix_prevents():
    """Before this fix, this exact f-string pattern would raise
    TypeError on a None value. Confirms it no longer does."""
    row = {'power.draw': None}
    try:
        result = f"{_safe_fmt(row.get('power.draw'))}W"
        check("the exact f-string pattern from the periodic print "
              "survives a None value without raising TypeError",
              result == "N/AW", f"got {result!r}")
    except TypeError as e:
        check("the exact f-string pattern from the periodic print "
              "survives a None value without raising TypeError",
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
