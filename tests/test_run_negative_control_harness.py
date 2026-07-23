# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
tests/test_run_negative_control_harness.py

Proves the CODE in scripts/run_negative_control.py is correct -- argument
parsing, the sample loop, error propagation, output format -- using a
mocked nvidia-smi. This is deliberately NOT a claim that detection works
on real hardware. It answers a narrower, still-useful question: "if I rent
a GPU right now and run this script, will it crash from a bug in the
script itself, wasting paid pod time?"

Three separate layers of confidence exist in this repo. Do not conflate
them:
  Layer 1 (test_engines.py, etc.) -- detector LOGIC is correct against
    synthetic data. Real, but says nothing about real hardware noise.
  Layer 2 (this file) -- the HARNESS wiring is correct: it parses args,
    calls the pipeline correctly, and produces the expected output shape,
    proven against a mocked nvidia-smi. Real, but the mock always returns
    clean data -- it cannot catch a case where real hardware behaves
    unexpectedly.
  Layer 3 (not done) -- actual behavior on a real, genuinely idle GPU.
    Nothing in this repository proves this yet. Only running
    scripts/run_negative_control.py for real, on real hardware, proves it.

Run: python tests/test_run_negative_control_harness.py
"""

import sys
import os
import io
import contextlib
import subprocess
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scripts.run_negative_control import sample_nvidia_smi, main

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


CLEAN_IDLE_LINE = "0, 80.36, 0, 0, 512, 42\n"


def test_sample_nvidia_smi_parses_valid_line():
    with patch('subprocess.check_output', return_value=CLEAN_IDLE_LINE):
        row = sample_nvidia_smi(gpu_index=0)
    check("sample_nvidia_smi: parses a valid CSV line into correct types",
          row['index'] == 0 and row['power.draw'] == 80.36
          and row['utilization.gpu'] == 0.0 and row['memory.used'] == 512.0
          and row['temperature.gpu'] == 42.0,
          f"got {row}")
    check("sample_nvidia_smi: compute_apps is None (documented gap, not "
          "silently faked)", row['compute_apps'] is None)


def test_sample_nvidia_smi_propagates_subprocess_errors():
    def raise_error(*a, **kw):
        raise subprocess.CalledProcessError(1, ['nvidia-smi'])
    with patch('subprocess.check_output', side_effect=raise_error):
        try:
            sample_nvidia_smi(gpu_index=0)
            check("sample_nvidia_smi: propagates subprocess errors "
                  "instead of swallowing them", False)
        except subprocess.CalledProcessError:
            check("sample_nvidia_smi: propagates subprocess errors "
                  "instead of swallowing them", True)


def test_sample_nvidia_smi_missing_binary_propagates():
    def raise_not_found(*a, **kw):
        raise FileNotFoundError("nvidia-smi not found")
    with patch('subprocess.check_output', side_effect=raise_not_found):
        try:
            sample_nvidia_smi(gpu_index=0)
            check("sample_nvidia_smi: missing binary raises, doesn't "
                  "silently fake a reading", False)
        except FileNotFoundError:
            check("sample_nvidia_smi: missing binary raises, doesn't "
                  "silently fake a reading", True)


def test_main_end_to_end_smoke_clean_idle_produces_zero_alerts():
    test_argv = ['run_negative_control.py', '--seconds', '1',
                 '--interval', '0.01', '--gpu', '0']
    captured = io.StringIO()
    crashed = False
    crash_reason = ""
    try:
        with patch('subprocess.check_output', return_value=CLEAN_IDLE_LINE), \
             patch('time.sleep', return_value=None), \
             patch.object(sys, 'argv', test_argv), \
             contextlib.redirect_stdout(captured):
            main()
    except SystemExit:
        pass
    except Exception as e:
        crashed = True
        crash_reason = repr(e)

    output = captured.getvalue()
    check("main(): runs end-to-end against mocked nvidia-smi without "
          "crashing", not crashed, f"raised {crash_reason}")
    check("main(): output reports the expected negative-control result "
          "label", "expect alerts == 0" in output, f"output was: {output!r}")
    check("main(): clean idle mocked data actually produces zero alerts "
          "through the real pipeline wiring",
          "'alerts': 0" in output, f"output was: {output!r}")
    check("main(): reports the sampling section", "Sampling" in output,
          f"output was: {output!r}")


def test_main_argument_parsing_defaults():
    test_argv = ['run_negative_control.py', '--seconds', '1',
                 '--interval', '0.01', '--gpu', '2']
    captured = io.StringIO()
    with patch('subprocess.check_output', return_value=CLEAN_IDLE_LINE), \
         patch('time.sleep', return_value=None), \
         patch.object(sys, 'argv', test_argv), \
         contextlib.redirect_stdout(captured):
        main()
    output = captured.getvalue()
    check("main(): --gpu argument reaches the header line",
          "GPU 2" in output, f"output was: {output!r}")


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
