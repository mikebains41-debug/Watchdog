# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
tests/test_check_pcie_telemetry.py

Layer 2 confidence only (see scripts/README.md for what that means): this
proves the SCRIPT's argument handling, error handling, and output shape
are correct, using mocked subprocess calls. It says nothing about what
real nvidia-smi dmon output actually looks like on real hardware -- that
is exactly the unknown this script exists to investigate, and mocking it
cannot resolve that unknown, only prove the surrounding code won't crash
when it gets a real answer.

Run: python tests/test_check_pcie_telemetry.py
"""

import sys
import os
import io
import contextlib
import subprocess
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scripts.check_pcie_telemetry import (
    check_static_link_info,
    check_dmon_throughput_mode,
    main,
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


def run_capturing(fn, *a, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = fn(*a, **kw)
    return result, buf.getvalue()


def test_link_info_success():
    fake_out = "3, 4, 16, 16\n"
    with patch('subprocess.check_output', return_value=fake_out):
        result, output = run_capturing(check_static_link_info)
    check("link_info: returns True on a valid CSV response", result is True)
    check("link_info: prints the raw CSV values", "3, 4, 16, 16" in output,
          f"output was: {output!r}")


def test_link_info_missing_binary():
    def raise_not_found(*a, **kw):
        raise FileNotFoundError()
    with patch('subprocess.check_output', side_effect=raise_not_found):
        result, output = run_capturing(check_static_link_info)
    check("link_info: returns False when nvidia-smi is missing",
          result is False)
    check("link_info: says so explicitly rather than crashing silently",
          "not found" in output.lower())


def test_link_info_process_error():
    def raise_err(*a, **kw):
        raise subprocess.CalledProcessError(1, ['nvidia-smi'])
    with patch('subprocess.check_output', side_effect=raise_err):
        result, output = run_capturing(check_static_link_info)
    check("link_info: returns False on a subprocess error", result is False)


def test_dmon_prints_raw_output_without_parsing_it():
    fake_out = "# gpu   rxpci   txpci\n# Idx    MB/s    MB/s\n    0      12       8\n"
    with patch('subprocess.check_output', return_value=fake_out):
        result, output = run_capturing(check_dmon_throughput_mode)
    check("dmon: returns True when it gets non-empty output", result is True)
    check("dmon: prints the raw output verbatim, unparsed",
          "rxpci" in output and "txpci" in output,
          f"output was: {output!r}")
    check("dmon: does NOT claim to have parsed specific values -- only "
          "tells the human to read it themselves",
          "read the" in output.lower() or "read that" in output.lower()
          or "read the output" in output.lower(),
          f"output was: {output!r}")


def test_dmon_empty_output_is_a_warning_not_a_crash():
    with patch('subprocess.check_output', return_value=""):
        result, output = run_capturing(check_dmon_throughput_mode)
    check("dmon: returns False on empty output (doesn't fabricate a pass)",
          result is False)


def test_dmon_blocked_in_container_reported_clearly():
    def raise_err(*a, **kw):
        raise subprocess.CalledProcessError(1, ['nvidia-smi', 'dmon'])
    with patch('subprocess.check_output', side_effect=raise_err):
        result, output = run_capturing(check_dmon_throughput_mode)
    check("dmon: CalledProcessError returns False, not a crash",
          result is False)
    check("dmon: explains this commonly means container restriction",
          "container" in output.lower())


def test_dmon_timeout_handled():
    def raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd=['nvidia-smi', 'dmon'], timeout=10)
    with patch('subprocess.check_output', side_effect=raise_timeout):
        result, output = run_capturing(check_dmon_throughput_mode)
    check("dmon: timeout returns False, not an unhandled exception",
          result is False)


def test_main_exit_code_reflects_link_info_success():
    def fake_check_output(cmd, **kw):
        if 'dmon' in cmd:
            return "# gpu rxpci txpci\n0 5 3\n"
        return "3, 4, 16, 16\n"

    with patch('subprocess.check_output', side_effect=fake_check_output):
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                main()
            exit_code = 0
        except SystemExit as e:
            exit_code = e.code

    check("main(): exit code 0 when link info succeeds", exit_code == 0,
          f"got {exit_code}")
    check("main(): prints a SUMMARY section", "SUMMARY" in buf.getvalue())


def test_main_exit_code_reflects_link_info_failure():
    def raise_not_found(*a, **kw):
        raise FileNotFoundError()

    with patch('subprocess.check_output', side_effect=raise_not_found):
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                main()
            exit_code = 0
        except SystemExit as e:
            exit_code = e.code

    check("main(): exit code 1 when nvidia-smi is entirely unavailable",
          exit_code == 1, f"got {exit_code}")


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
