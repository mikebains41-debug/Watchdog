"""
Module 104 — System Entropy Health Check

METHOD: module92 flagged a WARN about key generation occurring within
5 minutes of system boot — a documented real risk pattern (drawing
from a still-filling entropy pool). This module follows up directly:
checks the REAL, current entropy pool state and whether a hardware RNG
is actually available and in use on this system, right now.

HONESTY NOTE: entropy_avail readings are a live, instant-in-time
snapshot — they fluctuate constantly under normal operation and a
single low reading is not automatically alarming. This script reports
the real number and lets you interpret it, rather than asserting a
verdict from one sample.
"""
import subprocess
import json
import datetime
import os

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def read_entropy_avail():
    path = "/proc/sys/kernel/random/entropy_avail"
    try:
        with open(path) as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return None
    except PermissionError:
        return "permission_denied"
    except Exception as e:
        return f"error: {type(e).__name__}: {e}"


def check_hwrng_present():
    """Checks for a hardware RNG device — real evidence of whether
    entropy is coming from a dedicated hardware source vs. software
    estimation only."""
    hwrng_paths = [
        "/dev/hwrng",
        "/sys/devices/virtual/misc/hw_random/rng_available",
    ]
    findings = {}
    for path in hwrng_paths:
        findings[path] = os.path.exists(path)
    return findings


def check_rngd_running():
    """Checks whether an entropy-gathering daemon (rngd/haveged) is
    actively running — real process check, not assumed."""
    try:
        out = subprocess.run(
            ["pgrep", "-la", "rngd"],
            capture_output=True, text=True, timeout=5
        )
        rngd_running = bool(out.stdout.strip())

        out2 = subprocess.run(
            ["pgrep", "-la", "haveged"],
            capture_output=True, text=True, timeout=5
        )
        haveged_running = bool(out2.stdout.strip())

        return {"rngd_running": rngd_running, "haveged_running": haveged_running}
    except FileNotFoundError:
        return {"error": "pgrep not available — cannot check running daemons"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def run_check():
    print("--- Checking live entropy pool state ---")
    entropy = read_entropy_avail()
    print(f"Current entropy_avail: {entropy}")
    # Linux entropy pool is typically sized ~4096 bits max on modern kernels
    if isinstance(entropy, int):
        pct_of_typical_max = round((entropy / 4096) * 100, 1)
        print(f"  (~{pct_of_typical_max}% of a typical 4096-bit pool max — "
              f"context, not a verdict)")

    print("\n--- Checking for hardware RNG device ---")
    hwrng = check_hwrng_present()
    for path, present in hwrng.items():
        print(f"  {path}: {'present' if present else 'not present'}")

    print("\n--- Checking for entropy-gathering daemons ---")
    daemons = check_rngd_running()
    print(f"  {daemons}")

    hwrng_available = any(hwrng.values())
    daemon_running = daemons.get("rngd_running", False) or daemons.get("haveged_running", False)
    mitigating_factor_present = hwrng_available or daemon_running

    if mitigating_factor_present:
        risk_note = ("a hardware RNG and/or active daemon reduces that "
                      "specific risk")
    else:
        risk_note = ("without a hardware RNG or active entropy daemon, this "
                      "system relies on the kernel's software entropy "
                      "estimation alone, which is the exact condition "
                      "module92 flagged as elevated-risk near boot")

    print(f"\n{'='*60}")
    finding = (
        f"Current entropy pool reading: {entropy}. "
        f"Hardware RNG device present: {hwrng_available}. "
        f"Entropy-gathering daemon active: {daemon_running}. "
        f"This directly follows up on module92's WARN about near-boot "
        f"key generation risk — {risk_note}."
    )
    print(f"FINDING: {finding}")
    print(f"{'='*60}")

    return {
        "entropy_avail_current_reading": entropy,
        "hwrng_device_findings": hwrng,
        "hwrng_available": hwrng_available,
        "entropy_daemon_findings": daemons,
        "entropy_daemon_running": daemon_running,
        "finding": finding,
        "timestamp": now_iso(),
    }


if __name__ == "__main__":
    result = run_check()

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module104_entropy_health_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
