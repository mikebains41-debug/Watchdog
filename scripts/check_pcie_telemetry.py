#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
scripts/check_pcie_telemetry.py

Reconnaissance only -- this is NOT a detector. It answers one question:
does this environment's nvidia-smi expose enough PCIe telemetry to build
a "PCIe bandwidth anomaly detection" idea (e.g. slow model-weight
exfiltration over PCIe while GPU compute utilization stays at 0%) before
any detection code gets written for it.

WHY THIS EXISTS
  Every real detector in this repo was built against a signal confirmed
  present first -- ghost power, VRAM residual, and throughput contention
  were all observed before a detector was written for them. PCIe
  bandwidth is different: standard `nvidia-smi --query-gpu` CSV mode
  reliably exposes PCIe LINK info (generation, width -- static capability
  of the slot), but NOT real-time PCIe THROUGHPUT (bytes/sec actually
  moving). That needs a different invocation (`nvidia-smi dmon`), whose
  column format could not be verified against real hardware by whoever
  wrote this script, and may vary by driver version and container
  restrictions.

WHAT THIS SCRIPT DOES
  1. Queries static PCIe link info via --query-gpu (reliable, well-
     documented fields, safely parsed).
  2. Attempts `nvidia-smi dmon -c 1 -s t` and prints the RAW output rather
     than parsing it. It does not guess at column meanings it cannot
     verify. A human needs to read that output and confirm what it
     actually shows before any parsing code gets written against it.

WHAT THIS SCRIPT DOES NOT DO
  It does not detect anything. It does not conclude whether a PCIe
  detector is buildable -- it gathers the one piece of evidence (does
  dmon -s t work here, and what does its output look like) that
  determines that.

Usage:
  python3 scripts/check_pcie_telemetry.py
"""

import subprocess
import sys


LINK_FIELDS = (
    "pcie.link.gen.current,pcie.link.gen.max,"
    "pcie.link.width.current,pcie.link.width.max"
)


def check_static_link_info():
    print("=" * 60)
    print("1. STATIC PCIe LINK INFO (nvidia-smi --query-gpu)")
    print("=" * 60)
    try:
        out = subprocess.check_output(
            ["nvidia-smi", f"--query-gpu={LINK_FIELDS}",
             "--format=csv,noheader"],
            text=True, timeout=5,
        )
        print(out.strip())
        print("\n[INFO] These are STATIC capability fields (link generation")
        print("       and lane width). They do NOT measure real-time")
        print("       PCIe throughput -- see section 2.")
        return True
    except FileNotFoundError:
        print("[FAIL] nvidia-smi not found on PATH. Nothing further to")
        print("       check -- this environment has no GPU visible to it.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[FAIL] nvidia-smi returned an error: {e}")
        return False
    except Exception as e:
        print(f"[FAIL] Unexpected error querying link info: {e!r}")
        return False


def check_dmon_throughput_mode():
    print("\n" + "=" * 60)
    print("2. REAL-TIME PCIe THROUGHPUT (nvidia-smi dmon -s t)")
    print("=" * 60)
    print("[INFO] Printing RAW output. This script does not parse dmon's")
    print("       columns -- their exact format was not verified against")
    print("       real hardware when this script was written. Read the")
    print("       output below yourself before writing any parsing code")
    print("       against it.\n")
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "dmon", "-c", "1", "-s", "t"],
            text=True, timeout=10,
        )
        print(out)
        if not out.strip():
            print("[WARN] dmon ran but produced no output. PCIe throughput")
            print("       monitoring may not be supported in this")
            print("       environment (e.g. inside some containers).")
            return False
        print("[INFO] If you see rxpci/txpci columns with numeric values")
        print("       above, real-time PCIe throughput monitoring works")
        print("       here. If you see an error or garbage instead, it")
        print("       doesn't -- common inside restricted containers.")
        return True
    except FileNotFoundError:
        print("[FAIL] nvidia-smi not found.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[FAIL] nvidia-smi dmon returned an error: {e}")
        print("       This commonly means dmon-style monitoring is")
        print("       blocked in this container even though basic")
        print("       --query-gpu calls work.")
        return False
    except subprocess.TimeoutExpired:
        print("[FAIL] nvidia-smi dmon timed out. It may be waiting on")
        print("       something this environment doesn't support.")
        return False
    except Exception as e:
        print(f"[FAIL] Unexpected error running dmon: {e!r}")
        return False


def main():
    link_ok = check_static_link_info()
    dmon_ok = check_dmon_throughput_mode()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Static PCIe link info available:   {'YES' if link_ok else 'NO'}")
    print(f"Real-time PCIe throughput (dmon):  "
          f"{'MAYBE -- read raw output above' if dmon_ok else 'NO'}")
    print("=" * 60)
    print("This script does not conclude whether a PCIe bandwidth")
    print("detector is buildable. That conclusion requires a human to")
    print("read section 2's raw output and confirm it contains real,")
    print("changing throughput numbers during an actual active PCIe")
    print("transfer -- not just at idle.")
    print("=" * 60)

    sys.exit(0 if link_ok else 1)


if __name__ == "__main__":
    main()
