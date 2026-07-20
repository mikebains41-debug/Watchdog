#!/usr/bin/env python3
"""
scripts/hardware_preflight_check.py

Run this FIRST, on the very first rented GPU instance, before starting any
real Watchdog validation session. Answers two questions that determine
whether tonight's fixes actually work here, not just in mocked tests:

  1. Does every field in agent/telemetry.py's QUERY_FIELDS actually come
     back from THIS instance's nvidia-smi/driver? sample_gpu() silently
     drops an entire row if the column count doesn't match expectations
     (if len(vals) < len(QUERY_FIELDS): continue) -- so one unsupported
     field on one particular driver version means an empty run with NO
     error message telling you why. This script isolates which field, if
     any, is the problem, instead of leaving you to guess.

  2. Does --query-compute-apps actually return a process once one is
     running? All 14 tests for the compute_apps fix were mocked -- real
     proof that VRAMResidualDetector gets real data has never happened.
     This script walks you through starting a trivial workload and
     checks whether it shows up.

STATUS: unexecuted. No GPU exists in the environment that wrote this.
Do not treat its logic as validated until it has actually been run.

Usage:
  python3 scripts/hardware_preflight_check.py
  python3 scripts/hardware_preflight_check.py --skip-process-check
"""

import argparse
import subprocess
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from agent.telemetry import QUERY_FIELDS, COMPUTE_APPS_FIELDS, sample_gpu, sample_compute_apps


def check_nvidia_smi_present():
    print("=" * 60)
    print("1. nvidia-smi PRESENCE")
    print("=" * 60)
    try:
        r = subprocess.run(['nvidia-smi', '--query-gpu=name', '--format=csv,noheader'],
                            capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            print(f"[PASS] nvidia-smi found. GPU(s): {r.stdout.strip()}")
            return True
        print(f"[FAIL] nvidia-smi ran but returned nothing usable.")
        print(f"       stdout: {r.stdout!r}")
        print(f"       stderr: {r.stderr!r}")
        return False
    except FileNotFoundError:
        print("[FAIL] nvidia-smi not found on PATH. Nothing further to check.")
        return False
    except Exception as e:
        print(f"[FAIL] Unexpected error: {e!r}")
        return False


def diagnose_query_gpu_fields():
    print("\n" + "=" * 60)
    print("2. QUERY_FIELDS COMPATIBILITY")
    print("=" * 60)
    print(f"[INFO] Checking {len(QUERY_FIELDS)} fields as one combined "
          f"query -- this is exactly what sample_gpu() runs.")

    cmd = ['nvidia-smi', '--query-gpu=' + ','.join(QUERY_FIELDS),
           '--format=csv,noheader,nounits']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except Exception as e:
        print(f"[FAIL] Combined query itself failed to run: {e!r}")
        return False

    lines = [l for l in r.stdout.strip().split('\n') if l.strip()]
    if not lines:
        print(f"[FAIL] Combined query returned no rows.")
        print(f"       stderr: {r.stderr.strip()!r}")
    else:
        first_row_cols = len(lines[0].split(','))
        if first_row_cols == len(QUERY_FIELDS):
            print(f"[PASS] Combined query returned {first_row_cols} columns, "
                  f"matching all {len(QUERY_FIELDS)} expected fields. "
                  f"sample_gpu() will not silently drop rows here.")
            return True
        print(f"[FAIL] Combined query returned {first_row_cols} columns, "
              f"expected {len(QUERY_FIELDS)}. sample_gpu() would silently "
              f"drop every row -- diagnosing which field is the problem...")

    print("\n[INFO] Testing each field individually (one query per field, "
          "this will take a few seconds):")
    working, broken = [], []
    for field in QUERY_FIELDS:
        single_cmd = ['nvidia-smi', f'--query-gpu={field}',
                      '--format=csv,noheader,nounits']
        try:
            sr = subprocess.run(single_cmd, capture_output=True, text=True, timeout=5)
            if sr.returncode == 0 and sr.stdout.strip():
                working.append(field)
            else:
                broken.append((field, (sr.stderr.strip() or sr.stdout.strip() or
                                        "empty output, no error")))
        except Exception as e:
            broken.append((field, repr(e)))

    print(f"\n[RESULT] {len(working)}/{len(QUERY_FIELDS)} fields work individually.")
    if broken:
        print("[BROKEN FIELDS -- these need to come out of QUERY_FIELDS in "
              "agent/telemetry.py for this instance/driver, or the whole "
              "collector will silently produce zero rows]:")
        for field, reason in broken:
            print(f"    - {field}: {reason}")
    return len(broken) == 0


def check_compute_apps(interactive=True):
    print("\n" + "=" * 60)
    print("3. COMPUTE_APPS DETECTION (real process required)")
    print("=" * 60)
    print(f"[INFO] Querying with no process running first -- expect an "
          f"empty result. This is the normal, common state.")
    baseline = sample_compute_apps()
    print(f"       Result: {baseline}")
    if baseline:
        print("[NOTE] Non-empty even with (what you believe is) nothing "
              "running -- either something else is already using this "
              "GPU, or this confirms the query mechanism works. Either "
              "way, worth understanding before proceeding.")

    if not interactive:
        print("[SKIPPED] --skip-process-check passed; not waiting for a "
              "live workload. Re-run without that flag to confirm "
              "compute_apps actually detects a real process.")
        return None

    print("\n[ACTION REQUIRED] In another terminal on this same instance, "
          "start a trivial GPU workload, e.g.:")
    print("    python3 -c \"import torch; x=torch.zeros(4000,4000).cuda(); "
          "import time; time.sleep(30)\"")
    input("Press Enter here once that's running... ")

    result = sample_compute_apps()
    print(f"       Result with workload running: {result}")
    if result:
        print("[PASS] compute_apps detected a real process. "
              "VRAMResidualDetector will get real data on this instance.")
        return True
    print("[FAIL] compute_apps came back empty even with a workload "
          "running. Either the workload didn't actually start, or "
          "--query-compute-apps doesn't work as expected in this "
          "environment -- investigate before trusting VRAMResidualDetector "
          "here.")
    return False


_UNSET = object()


def check_torch_cuda(torch_module=_UNSET):
    """
    Checks whether torch is installed with working CUDA support --
    required by scripts/precision_ghost_power_benchmark.py, NOT required
    by core Watchdog detector validation (which never imports torch).

    Separate check from nvidia-smi deliberately: a GPU can be fully
    visible to nvidia-smi while torch itself is either not installed,
    installed without CUDA support, or built against a CUDA version that
    doesn't match this instance's driver -- any of which makes
    torch.cuda.is_available() return False with no other obvious error,
    and would otherwise only be discovered mid-benchmark.

    torch_module is injectable for testing this function's logic without
    needing torch installed or a real GPU. Left at the _UNSET sentinel
    (not None), a real `import torch` is attempted; explicitly passing
    torch_module=None simulates "torch is not installed" for tests.
    """
    print("\n" + "=" * 60)
    print("4. TORCH + CUDA (required for precision_ghost_power_benchmark.py, "
          "NOT required for core Watchdog detector validation)")
    print("=" * 60)

    if torch_module is _UNSET:
        try:
            import torch as t
        except ImportError:
            t = None
    else:
        t = torch_module

    if t is None:
        print("[FAIL] torch is not installed.")
        print("       Install with: pip install torch --break-system-packages")
        print("       (or the equivalent for this instance's package manager)")
        return False

    print(f"[INFO] torch version: {getattr(t, '__version__', 'unknown')}")

    if not t.cuda.is_available():
        print("[FAIL] torch.cuda.is_available() is False -- torch is "
              "installed but cannot see a CUDA GPU. This can happen even "
              "when nvidia-smi works fine: the installed torch build may "
              "lack CUDA support, or may be built against a CUDA version "
              "that doesn't match this instance's driver.")
        print("       Check: pip show torch  (look for a '+cuXXX' build tag)")
        return False

    gpu_name = t.cuda.get_device_name(0)
    print(f"[PASS] torch sees a CUDA GPU: {gpu_name}")

    fp8_supported = hasattr(t, 'float8_e4m3fn') and hasattr(t, '_scaled_mm')
    int8_supported = hasattr(t, '_int_mm')
    print(f"[INFO] FP8 matmul support (torch-level): "
          f"{'available' if fp8_supported else 'NOT available -- fp8 will report UNSUPPORTED in the benchmark'}")
    print(f"[INFO] INT8 matmul support (torch-level): "
          f"{'available' if int8_supported else 'NOT available -- int8 will report UNSUPPORTED in the benchmark'}")
    print("[INFO] FP4 has no vanilla-PyTorch path on any hardware -- "
          "always reports UNSUPPORTED in the benchmark regardless of "
          "this instance. Expected, not a problem to fix.")

    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skip-process-check', action='store_true',
                         help="Skip the interactive live-process check")
    parser.add_argument('--skip-torch-check', action='store_true',
                         help="Skip the torch/CUDA check (only needed for "
                              "the precision benchmark script, not core "
                              "Watchdog detector validation)")
    args = parser.parse_args()

    smi_ok = check_nvidia_smi_present()
    if not smi_ok:
        print("\n[ABORT] nvidia-smi isn't working -- nothing else here "
              "can be meaningfully checked.")
        sys.exit(1)

    fields_ok = diagnose_query_gpu_fields()
    apps_result = check_compute_apps(interactive=not args.skip_process_check)
    torch_result = None if args.skip_torch_check else check_torch_cuda()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"nvidia-smi present:        {'YES' if smi_ok else 'NO'}")
    print(f"QUERY_FIELDS all supported: {'YES' if fields_ok else 'NO -- see above'}")
    if apps_result is None:
        print("compute_apps detection:    NOT CHECKED (--skip-process-check)")
    else:
        print(f"compute_apps detection:    {'YES' if apps_result else 'NO -- see above'}")
    if torch_result is None:
        print("torch + CUDA (precision benchmark): NOT CHECKED (--skip-torch-check)")
    else:
        print(f"torch + CUDA (precision benchmark): {'YES' if torch_result else 'NO -- see above'}")
    print("=" * 60)

    if not fields_ok or apps_result is False:
        print("Do not start a paid validation session until the issues "
              "above are resolved -- they will silently produce empty or "
              "wrong results, not an obvious error.")
        sys.exit(1)

    print("Clear to proceed with real Watchdog validation on this instance.")
    if torch_result is False:
        print("Note: torch/CUDA is NOT working here -- core Watchdog "
              "detector validation can still proceed, but "
              "scripts/precision_ghost_power_benchmark.py will not run "
              "until that's fixed (see above for the exact issue).")


if __name__ == '__main__':
    main()
