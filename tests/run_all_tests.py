#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
# Watchdog - Validation Suite (only real, confirmed-existing scripts)
import sys, subprocess
from datetime import datetime

def run_test(name, script, args=[]):
    print(f"\n[TEST] {name}")
    try:
        r = subprocess.run([sys.executable, script] + args, capture_output=True, text=True, timeout=3600)
        print(r.stdout)
        return r.returncode == 0
    except Exception as e:
        print(f"FAILED: {e}")
        return False

def main():
    tests = [
        ("Container Escape", "tests/container_escape_test.py"),
        ("Compliance Evidence", "tests/compliance_evidence_test.py"),
    ]
    results = {name: run_test(name, script) for name, script in tests}
    print("\n=== SUMMARY ===")
    for name, ok in results.items():
        print(f"{'PASS' if ok else 'FAIL'}: {name}")
    print("\nNOTE: stability_test.py, false_positive_benchmark.py, latency_test.py,")
    print("and swarm_test.py require real GPU hardware / running servers and are")
    print("NOT included in this automated suite -- run them manually when hardware")
    print("is available.")
    sys.exit(0 if all(results.values()) else 1)

if __name__ == "__main__":
    main()
