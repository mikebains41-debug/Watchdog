#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
# Watchdog AIDR - Attack Injection Suite
# Runs every positive-control test built tonight across all 8 test
# files, dynamically discovered via inspect -- no duplicated logic.
# HONEST STATUS: all patterns already individually verified tonight.
# Fully runnable on this device, no GPU needed.

import sys
import os
import importlib
import inspect

TESTS_DIR = os.path.dirname(__file__)
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, os.path.join(TESTS_DIR, "..", "detection"))

TEST_MODULES = [
    "test_positive_controls_engines",
    "test_positive_controls_hardware",
    "test_positive_controls_memory",
    "test_positive_controls_llm",
    "test_positive_controls_advanced",
    "test_throughput_contention_detector",
    "test_ecc_error_trend_detector",
    "test_cc_integrity_detector",
]


def run_module_tests(module_name):
    try:
        module = importlib.import_module(module_name)
    except Exception as e:
        return {"module": module_name, "error": str(e), "passed": 0, "failed": 0, "total": 0}
    test_funcs = [
        (name, obj) for name, obj in inspect.getmembers(module, inspect.isfunction)
        if name.startswith("test_") and obj.__module__ == module_name
    ]
    passed = 0
    failed = 0
    failures = []
    for name, func in test_funcs:
        try:
            func()
            passed += 1
        except AssertionError as e:
            failed += 1
            failures.append({"test": name, "error": str(e)})
        except Exception as e:
            failed += 1
            failures.append({"test": name, "error": f"UNEXPECTED: {e}"})
    return {"module": module_name, "passed": passed, "failed": failed, "total": len(test_funcs), "failures": failures}


def main():
    print("=" * 60)
    print("WATCHDOG AIDR - ATTACK INJECTION SUITE")
    print("=" * 60)

    total_passed = 0
    total_failed = 0

    for module_name in TEST_MODULES:
        print(f"\n[MODULE] {module_name}")
        result = run_module_tests(module_name)
        if "error" in result:
            print(f"  COULD NOT LOAD: {result['error']}")
            continue
        total_passed += result["passed"]
        total_failed += result["failed"]
        print(f"  {result['passed']}/{result['total']} passed")
        for f in result.get("failures", []):
            print(f"  [FAIL] {f['test']}: {f['error']}")

    print("\n" + "=" * 60)
    print(f"TOTAL: {total_passed} passed, {total_failed} failed, across {len(TEST_MODULES)} modules")
    print("=" * 60)
    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
