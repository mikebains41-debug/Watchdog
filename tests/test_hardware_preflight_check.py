# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
tests/test_hardware_preflight_check.py

Layer 2 confidence only (see scripts/README.md): proves this script's
diagnostic LOGIC is correct against mocked nvidia-smi output. Cannot and
does not prove anything about what a real driver actually returns -- that
is exactly what this script exists to check once real hardware exists.

Run: python tests/test_hardware_preflight_check.py
"""

import sys
import os
import io
import contextlib
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scripts.hardware_preflight_check import (
    check_nvidia_smi_present,
    diagnose_query_gpu_fields,
    check_compute_apps,
)
from agent.telemetry import QUERY_FIELDS

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def fake_proc(stdout="", stderr="", returncode=0):
    class R:
        pass
    r = R()
    r.stdout, r.stderr, r.returncode = stdout, stderr, returncode
    return r


def run_capturing(fn, *a, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = fn(*a, **kw)
    return result, buf.getvalue()


def test_nvidia_smi_present_pass():
    with patch('subprocess.run', return_value=fake_proc(stdout="NVIDIA H200\n")):
        result, out = run_capturing(check_nvidia_smi_present)
    check("nvidia_smi_present: PASS when it returns a GPU name",
          result is True, f"got {result}")


def test_nvidia_smi_missing():
    def raise_nf(*a, **kw):
        raise FileNotFoundError()
    with patch('subprocess.run', side_effect=raise_nf):
        result, out = run_capturing(check_nvidia_smi_present)
    check("nvidia_smi_present: FAIL cleanly when binary missing",
          result is False, f"got {result}")


def test_all_fields_working_no_bisection_needed():
    combined_line = ",".join(["x"] * len(QUERY_FIELDS))
    call_count = {'n': 0}

    def fake_run(cmd, **kw):
        call_count['n'] += 1
        return fake_proc(stdout=combined_line + "\n")

    with patch('subprocess.run', side_effect=fake_run):
        result, out = run_capturing(diagnose_query_gpu_fields)

    check("diagnose_fields: PASS when combined query has correct column count",
          result is True, f"got {result}")
    check("diagnose_fields: does not run per-field bisection when combined "
          "query already succeeded (only 1 subprocess call, not "
          f"{len(QUERY_FIELDS)}+1)",
          call_count['n'] == 1, f"made {call_count['n']} calls")


def test_missing_field_correctly_identified():
    broken_field = QUERY_FIELDS[5]

    short_line = ",".join(["x"] * (len(QUERY_FIELDS) - 1))

    def fake_run(cmd, **kw):
        cmd_str = cmd[1]
        if cmd_str.startswith('--query-gpu=' + broken_field) and ',' not in cmd_str[len('--query-gpu='):]:
            return fake_proc(stdout="", stderr="Field not supported", returncode=1)
        if cmd_str == '--query-gpu=' + ','.join(QUERY_FIELDS):
            return fake_proc(stdout=short_line + "\n")
        return fake_proc(stdout="x\n")

    with patch('subprocess.run', side_effect=fake_run):
        result, out = run_capturing(diagnose_query_gpu_fields)

    check("diagnose_fields: returns False when a field is broken",
          result is False)
    check("diagnose_fields: names the specific broken field in output",
          broken_field in out, f"output was: {out[-500:]}")


def test_compute_apps_skipped_when_flag_set():
    with patch('subprocess.run', return_value=fake_proc(stdout="")):
        result, out = run_capturing(check_compute_apps, interactive=False)
    check("compute_apps: returns None (not checked) when interactive=False",
          result is None, f"got {result}")
    check("compute_apps: says SKIPPED in output, doesn't pretend to have "
          "verified anything", "SKIPPED" in out, f"output: {out}")


def test_compute_apps_detects_process_when_present():
    call_n = {'n': 0}

    def fake_run(cmd, **kw):
        call_n['n'] += 1
        if call_n['n'] == 1:
            return fake_proc(stdout="")
        return fake_proc(stdout="GPU-aaaa, 999, 4096\n")

    with patch('subprocess.run', side_effect=fake_run), \
         patch('builtins.input', return_value=""):
        result, out = run_capturing(check_compute_apps, interactive=True)

    check("compute_apps: PASS when a process appears after the prompt",
          result is True, f"got {result}")


def test_compute_apps_fails_when_still_empty():
    with patch('subprocess.run', return_value=fake_proc(stdout="")), \
         patch('builtins.input', return_value=""):
        result, out = run_capturing(check_compute_apps, interactive=True)
    check("compute_apps: FAIL when still empty after the prompt (workload "
          "didn't start, or query doesn't work here)",
          result is False, f"got {result}")


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
