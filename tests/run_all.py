#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/run_all.py

Runs every test_*.py file in tests/ as a subprocess, in isolation from each
other, and reports a combined PASS/FAIL total. Each test file already
prints its own PASSED/FAILED breakdown when run alone -- this script does
not duplicate that logic, it just runs each one and parses the final line.

Deliberately excludes anything that isn't a real automated test:
  scripts/run_negative_control.py is NOT included here. It requires live
  GPU hardware, is not automated (it runs for up to an hour and needs a
  human to confirm the GPU was actually idle throughout), and as of this
  writing has never been executed. Including it in an automated suite
  would misrepresent it as something that runs and passes on every commit.

Usage:
  python3 tests/run_all.py
"""

import subprocess
import sys
import re
import os

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TEST_DIR)

TEST_FILES = [
    "test_engines.py",
    "test_throughput_contention.py",
    "test_sampler.py",
    "test_cei_report.py",
    "test_verify_ebpf_quarantine_core.py",
    "test_run_negative_control_harness.py",
    "test_check_pcie_telemetry.py",
    "test_ai_attack_detectors.py",
    "test_ai_attack_detectors_batch2.py",
    "test_security_swarm.py",
    "test_remediation_and_investigator.py",
    "test_aibom_and_hardening.py",
    "test_aibom_jurisdictions.py",
    "test_saas_scaffold.py",
]

RESULT_RE = re.compile(r"PASSED:\s*(\d+)\s+FAILED:\s*(\d+)")


def run_one(filename):
    path = os.path.join(TEST_DIR, filename)
    if not os.path.exists(path):
        return {"file": filename, "ok": False, "error": "file not found",
                "passed": 0, "failed": 0}

    proc = subprocess.run(
        [sys.executable, path],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )

    match = RESULT_RE.search(proc.stdout)
    if not match:
        return {
            "file": filename, "ok": False,
            "error": "could not parse PASSED/FAILED line -- see raw output",
            "passed": 0, "failed": 0,
            "stdout_tail": proc.stdout[-500:],
            "stderr_tail": proc.stderr[-500:],
        }

    passed, failed = int(match.group(1)), int(match.group(2))
    return {"file": filename, "ok": failed == 0 and proc.returncode == 0,
            "passed": passed, "failed": failed}


def main():
    results = [run_one(f) for f in TEST_FILES]

    print("=" * 60)
    print("WATCHDOG TEST SUITE")
    print("=" * 60)

    total_passed = 0
    total_failed = 0
    any_error = False

    for r in results:
        if "error" in r:
            print(f"[ERROR] {r['file']}: {r['error']}")
            if 'stdout_tail' in r:
                print(f"        last stdout: {r['stdout_tail']!r}")
            any_error = True
            continue
        status = "OK" if r["ok"] else "FAIL"
        print(f"[{status:4}] {r['file']:40} "
              f"passed={r['passed']:3}  failed={r['failed']:3}")
        total_passed += r["passed"]
        total_failed += r["failed"]

    print("=" * 60)
    print(f"TOTAL: {total_passed} passed, {total_failed} failed "
          f"across {len(TEST_FILES)} files")
    print("=" * 60)
    print("Not included above (requires live GPU hardware, unexecuted):")
    print("  scripts/run_negative_control.py")
    print("=" * 60)

    if any_error or total_failed > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
