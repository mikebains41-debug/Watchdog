# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_hardware_preflight_torch_check.py

Tests for check_torch_cuda(), added to scripts/hardware_preflight_check.py.
Proves the logic against an injected fake torch module -- proves nothing
about what a real instance's torch/CUDA setup actually looks like.

Run: python tests/test_hardware_preflight_torch_check.py
"""

import sys
import os
import io
import contextlib
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scripts.hardware_preflight_check import check_torch_cuda

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


def test_fails_cleanly_when_torch_not_installed():
    result, out = run_capturing(check_torch_cuda, torch_module=None)
    check("check_torch_cuda: returns False when torch is None (not "
          "installed)", result is False, f"got {result}")
    check("check_torch_cuda: tells the user how to install it",
          "pip install torch" in out, f"output: {out}")


def test_fails_cleanly_when_cuda_not_available():
    fake_torch = MagicMock()
    fake_torch.__version__ = '2.5.0'
    fake_torch.cuda.is_available.return_value = False
    result, out = run_capturing(check_torch_cuda, torch_module=fake_torch)
    check("check_torch_cuda: returns False when cuda.is_available() is False",
          result is False, f"got {result}")
    check("check_torch_cuda: explains this can happen even when "
          "nvidia-smi works", "even when" in out, f"output: {out}")


def test_passes_and_reports_gpu_when_cuda_available():
    fake_torch = MagicMock()
    fake_torch.__version__ = '2.5.0'
    fake_torch.cuda.is_available.return_value = True
    fake_torch.cuda.get_device_name.return_value = 'NVIDIA H200'
    # No fp8/int8 attrs on this fake -- simulates an older torch build
    del fake_torch.float8_e4m3fn
    del fake_torch._scaled_mm
    del fake_torch._int_mm
    result, out = run_capturing(check_torch_cuda, torch_module=fake_torch)
    check("check_torch_cuda: returns True when torch sees a CUDA GPU",
          result is True, f"got {result}")
    check("check_torch_cuda: reports the actual GPU name in output",
          'NVIDIA H200' in out, f"output: {out}")


def test_reports_fp8_unavailable_when_attrs_missing():
    fake_torch = MagicMock(spec=['__version__', 'cuda'])
    fake_torch.__version__ = '2.0.0'
    fake_torch.cuda.is_available.return_value = True
    fake_torch.cuda.get_device_name.return_value = 'NVIDIA A100'
    result, out = run_capturing(check_torch_cuda, torch_module=fake_torch)
    check("check_torch_cuda: still returns True overall (fp8 is "
          "informational, not blocking)", result is True, f"got {result}")
    check("check_torch_cuda: reports fp8 as NOT available when the "
          "required attributes are missing",
          'FP8' in out and 'NOT available' in out, f"output: {out}")


def test_reports_fp8_available_when_attrs_present():
    fake_torch = MagicMock()
    fake_torch.__version__ = '2.5.0'
    fake_torch.cuda.is_available.return_value = True
    fake_torch.cuda.get_device_name.return_value = 'NVIDIA H200'
    fake_torch.float8_e4m3fn = 'fake_dtype'
    fake_torch._scaled_mm = MagicMock()
    result, out = run_capturing(check_torch_cuda, torch_module=fake_torch)
    check("check_torch_cuda: reports fp8 as available when the "
          "attributes exist",
          'FP8' in out and 'available' in out and 'NOT available' not in out.split('FP8')[1].split('\n')[0],
          f"output: {out}")


def test_always_reports_fp4_unsupported():
    """FP4 has no vanilla-PyTorch path regardless of what the fake torch
    claims to support -- must be reported as expected/unsupported every
    time, not silently omitted."""
    fake_torch = MagicMock()
    fake_torch.__version__ = '2.5.0'
    fake_torch.cuda.is_available.return_value = True
    fake_torch.cuda.get_device_name.return_value = 'NVIDIA B200'
    result, out = run_capturing(check_torch_cuda, torch_module=fake_torch)
    check("check_torch_cuda: always notes FP4 has no vanilla PyTorch "
          "path, regardless of GPU", 'FP4' in out, f"output: {out}")


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
