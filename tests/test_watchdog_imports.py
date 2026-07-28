#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_watchdog_imports.py

Smoke test: does watchdog.py actually import, and does the real
pipeline construct?

WHY THIS EXISTS: a missing module (intelligence/compliance_metrics.py
was patched into watchdog.py's imports before the file itself was
created) broke watchdog.py completely -- and the full 36/36 test suite
still passed, because attack_injection_suite.py tests detector modules
directly and never imports the main entry point. A fresh clone would
have failed instantly on a bug the entire test suite reported as clean.
This is the cheapest possible guard against that whole class of gap.

Run: python tests/test_watchdog_imports.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def test_watchdog_module_imports():
    try:
        import watchdog
        check("watchdog.py imports without error", True)
    except Exception as e:
        check("watchdog.py imports without error", False, f"{e!r}")


def test_full_pipeline_constructs():
    try:
        from watchdog import FullDetectionPipeline
        p = FullDetectionPipeline(fleet_size=10)
        check("FullDetectionPipeline constructs", True)
        check("engine count is a positive integer",
              isinstance(p.total_engine_count, int) and p.total_engine_count > 0,
              f"got {p.total_engine_count}")
    except Exception as e:
        check("FullDetectionPipeline constructs", False, f"{e!r}")


def test_pipeline_processes_a_row_without_crashing():
    try:
        from watchdog import FullDetectionPipeline
        p = FullDetectionPipeline(fleet_size=10)
        row = {'index': 0, 'iso_timestamp': '2026-01-01T00:00:00',
               'power.draw': 100, 'utilization.gpu': 50, 'memory.used': 1000,
               'compute_apps': []}
        p.process(row)
        check("pipeline processes one real-shaped row", True)
    except Exception as e:
        check("pipeline processes one real-shaped row", False, f"{e!r}")


def test_api_server_imports():
    try:
        from api.server import handle_throughput_request, handle_hashrate_request
        check("api/server.py imports both request handlers", True)
    except Exception as e:
        check("api/server.py imports both request handlers", False, f"{e!r}")


if __name__ == '__main__':
    print("=== Smoke Test: main entry point imports and constructs ===\n")
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for t in tests:
        try:
            t()
        except Exception as e:
            check(t.__name__, False, f"EXCEPTION {e!r}")

    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
