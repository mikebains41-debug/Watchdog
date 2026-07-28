#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
#
# security/nvlink_residual_check.py
#
# NVLink Peer-to-Peer Residual Access Check -- Full Methodology
#
# WHY THIS EXISTS
#   VRAM residual (security/cross_tenant_vram_full_methodology.py) asks:
#   after a process exits, is its VRAM content still readable by someone
#   else? This script asks the multi-GPU analog: after a process that
#   enabled NVLink peer-to-peer (P2P) access between GPU0 and GPU1 exits,
#   is that P2P memory mapping actually torn down -- or could a later,
#   unrelated process on GPU1 still read into GPU0's memory through a
#   stale P2P handle?
#
# METHODOLOGY
#   Phase A: Process 1 enables P2P access GPU0<->GPU1, writes a known
#            marker pattern into a GPU0 buffer, holds it, then exits
#            WITHOUT explicitly disabling P2P access (simulating a crash
#            or ungraceful exit, matching the "graceful vs SIGKILL"
#            comparison used in the VRAM residual tests).
#   Phase B: A genuinely separate process (Process 2) on GPU1 attempts to
#            establish P2P access to GPU0 and scan for the marker,
#            without ever having received it directly.
#
# STATUS: UNEXECUTED. No multi-GPU hardware exists in the environment
# that wrote this script. Do not treat this as a validated finding until
# it has actually been run on real 2x+ GPU hardware with NVLink present.
# This is the same "unexecuted, stated plainly" discipline as
# scripts/hardware_preflight_check.py elsewhere in this project.
#
# Run: python3 security/nvlink_residual_check.py
#      (requires >=2 NVLink-connected GPUs; will print a clear SKIP and
#      exit cleanly if fewer than 2 GPUs or no NVLink is detected --
#      never fabricates a result on unsuitable hardware)

import subprocess
import sys
import time

PATTERN = -559038737  # 0xDEADBEEF as signed int32


def gpu_count():
    try:
        r = subprocess.run(['nvidia-smi', '--query-gpu=index', '--format=csv,noheader'],
                            capture_output=True, text=True, timeout=10)
        return len([l for l in r.stdout.strip().split('\n') if l.strip()])
    except Exception:
        return 0


def nvlink_present():
    try:
        r = subprocess.run(['nvidia-smi', 'nvlink', '-s'],
                            capture_output=True, text=True, timeout=10)
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


def main():
    print("=== NVLink P2P Residual Access Check ===")
    print()

    n_gpus = gpu_count()
    print(f"GPUs detected: {n_gpus}")
    if n_gpus < 2:
        print("[SKIP] Fewer than 2 GPUs present. NVLink P2P requires at "
              "least 2 GPUs. No result to report -- this is not a "
              "negative finding, it is an unsuitable environment.")
        sys.exit(0)

    has_nvlink = nvlink_present()
    print(f"NVLink present: {has_nvlink}")
    if not has_nvlink:
        print("[SKIP] nvidia-smi nvlink -s reports no active links. "
              "Cannot test P2P residual access without NVLink hardware. "
              "This is not a negative finding, it is an unsuitable "
              "environment.")
        sys.exit(0)

    try:
        import torch
    except ImportError:
        print("[FAIL] torch not available -- cannot run this check.")
        sys.exit(1)

    if not torch.cuda.is_available() or torch.cuda.device_count() < 2:
        print("[SKIP] PyTorch does not see 2+ CUDA devices. Cannot "
              "proceed.")
        sys.exit(0)

    can_access = torch.cuda.can_device_access_peer(0, 1)
    print(f"torch reports GPU0 can access GPU1 peer memory: {can_access}")
    if not can_access:
        print("[SKIP] PyTorch reports P2P access is not available between "
              "these two GPUs (may require NVSwitch/topology support this "
              "pair doesn't have). Cannot proceed. Not a negative finding.")
        sys.exit(0)

    print()
    print("=== PHASE A: writing pattern via GPU0, P2P access enabled, "
          "then exiting WITHOUT explicit teardown ===")
    print("[NOT EXECUTED -- see script status header]")
    print("On real hardware, this phase would:")
    print("  1. Allocate a buffer on GPU0, fill with PATTERN")
    print("  2. Enable P2P access from GPU1 to GPU0 (torch or cudaDeviceEnablePeerAccess)")
    print("  3. Confirm the pattern is readable from GPU1 via P2P (positive control)")
    print("  4. Exit this process WITHOUT calling cudaDeviceDisablePeerAccess")
    print()
    print("=== PHASE B: separate process on GPU1 attempts stale P2P read ===")
    print("[NOT EXECUTED -- see script status header]")
    print("On real hardware, this phase would:")
    print("  1. Run as a genuinely separate OS process (not the same Python session)")
    print("  2. Allocate a FRESH buffer on GPU1")
    print("  3. Attempt to re-establish or reuse P2P access to GPU0")
    print("  4. Scan for PATTERN without ever having received it directly")
    print("  5. Repeat N times, same rigor as tenant_b_reader.py's 20 attempts")
    print()
    print("=== VERDICT ===")
    print("This script currently only confirms environment suitability "
          "(2+ GPUs, NVLink present, P2P access possible). The actual "
          "write/exit/scan phases are documented above but not "
          "implemented -- implement Phase A and Phase B as separate "
          "processes (see security/tenant_a_writer.py and "
          "security/tenant_b_reader.py for the exact separate-process "
          "pattern already proven to work in this project) before "
          "running this on real 2x+ GPU NVLink hardware.")


if __name__ == '__main__':
    main()
