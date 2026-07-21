"""
tests/test_nvlink_telemetry.py

Tests parse_nvlink_output() against synthetic text shaped like NVIDIA's
documented `nvidia-smi nvlink -g <index> -gt d` output. This proves the
parsing logic is correct against that DOCUMENTED format. It does NOT
prove real nvidia-smi output matches this format on any given driver
version -- no GPU exists in the environment that wrote this to confirm
that. See scripts/hardware_preflight_check.py for where this needs
adding before trusting it on real hardware.

Run: python tests/test_nvlink_telemetry.py
"""

import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from agent.telemetry import parse_nvlink_output, sample_nvlink

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def fake_proc(stdout="", returncode=0):
    class R:
        pass
    r = R()
    r.stdout, r.returncode = stdout, returncode
    return r


def test_parses_documented_format_correctly():
    text = (
        "GPU 0: NVLink Data Tx:\n"
        "   Link 0: 1234 KiB\n"
        "   Link 1: 5678 KiB\n"
        "GPU 0: NVLink Data Rx:\n"
        "   Link 0: 2345 KiB\n"
        "   Link 1: 6789 KiB\n"
    )
    result = parse_nvlink_output(text)
    check("parses tx/rx sums correctly from the documented format",
          result['nvlink_available'] is True
          and result['nvlink_tx_kbs'] == 1234.0 + 5678.0
          and result['nvlink_rx_kbs'] == 2345.0 + 6789.0,
          f"got {result}")


def test_no_links_reports_unavailable():
    text = "GPU 0: NVLink not supported on this device\n"
    result = parse_nvlink_output(text)
    check("no Link lines found: reports unavailable, not zero traffic "
          "(absence and zero are different facts)",
          result['nvlink_available'] is False
          and result['nvlink_tx_kbs'] is None,
          f"got {result}")


def test_empty_output_reports_unavailable():
    result = parse_nvlink_output("")
    check("empty output: reports unavailable, no crash",
          result['nvlink_available'] is False, f"got {result}")


def test_single_link_sums_correctly():
    text = (
        "GPU 0: NVLink Data Tx:\n"
        "   Link 0: 500 KiB\n"
        "GPU 0: NVLink Data Rx:\n"
        "   Link 0: 750 KiB\n"
    )
    result = parse_nvlink_output(text)
    check("single-link GPU sums correctly (not assuming multi-link)",
          result['nvlink_tx_kbs'] == 500.0 and result['nvlink_rx_kbs'] == 750.0,
          f"got {result}")


def test_malformed_link_line_skipped_not_crashed():
    text = (
        "GPU 0: NVLink Data Tx:\n"
        "   Link 0: not_a_number KiB\n"
        "   Link 1: 100 KiB\n"
        "GPU 0: NVLink Data Rx:\n"
        "   Link 0: 200 KiB\n"
    )
    result = parse_nvlink_output(text)
    check("a malformed value line is skipped rather than crashing the "
          "whole parse, well-formed lines still counted",
          result['nvlink_available'] is True and result['nvlink_tx_kbs'] == 100.0,
          f"got {result}")


def test_sample_nvlink_handles_nonzero_returncode():
    with patch('subprocess.run', return_value=fake_proc(stdout="", returncode=1)):
        result = sample_nvlink(0)
    check("sample_nvlink: nonzero returncode (e.g. no NVLink hardware) "
          "reports unavailable, no crash",
          result['nvlink_available'] is False, f"got {result}")


def test_sample_nvlink_handles_subprocess_exception():
    def raise_err(*a, **kw):
        raise FileNotFoundError("nvidia-smi not found")
    with patch('subprocess.run', side_effect=raise_err):
        result = sample_nvlink(0)
    check("sample_nvlink: subprocess failure reports unavailable, "
          "does not propagate the exception",
          result['nvlink_available'] is False, f"got {result}")


def test_sample_nvlink_success_path():
    text = (
        "GPU 0: NVLink Data Tx:\n"
        "   Link 0: 1000 KiB\n"
        "GPU 0: NVLink Data Rx:\n"
        "   Link 0: 2000 KiB\n"
    )
    with patch('subprocess.run', return_value=fake_proc(stdout=text)):
        result = sample_nvlink(0)
    check("sample_nvlink: success path returns real parsed values",
          result['nvlink_available'] is True and result['nvlink_tx_kbs'] == 1000.0,
          f"got {result}")


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
