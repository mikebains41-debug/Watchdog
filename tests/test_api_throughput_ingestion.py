"""
tests/test_api_throughput_ingestion.py

Tests handle_throughput_request() -- the logic behind the /throughput
endpoint -- against a REAL DetectionPipeline instance, not a mock. This
proves the actual calibrate/process flow works end to end. It does NOT
test the FastAPI route wiring itself (request parsing, HTTP response
codes) -- fastapi is not installed in this environment or, as of
tonight, the target Termux environment, so that layer is unexecuted.

Run: python tests/test_api_throughput_ingestion.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.server import handle_throughput_request, set_pipeline, update_state, _state
from detection.engines import DetectionPipeline

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def test_no_pipeline_gives_clear_error_not_a_crash():
    result = handle_throughput_request(None, {"throughput": 300.0})
    check("no pipeline: returns a clear error dict, does not crash",
          "error" in result and "No pipeline attached" in result["error"],
          f"got {result}")


def test_missing_throughput_field():
    p = DetectionPipeline()
    result = handle_throughput_request(p, {})
    check("missing 'throughput' field: clear error, not a KeyError crash",
          "error" in result and "Missing required field" in result["error"],
          f"got {result}")


def test_non_numeric_throughput_field():
    p = DetectionPipeline()
    result = handle_throughput_request(p, {"throughput": "not-a-number"})
    check("non-numeric 'throughput': clear error, not an unhandled "
          "ValueError crash",
          "error" in result and "must be a number" in result["error"],
          f"got {result}")


def test_unknown_mode():
    p = DetectionPipeline()
    result = handle_throughput_request(p, {"throughput": 300.0, "mode": "bogus"})
    check("unknown mode: clear error naming the valid options",
          "error" in result and "calibrate" in result["error"] and "process" in result["error"],
          f"got {result}")


def test_calibrate_mode_feeds_real_detector():
    p = DetectionPipeline()
    check("before calibration: detector reports not calibrated",
          p.throughput_contention.calibrated is False)

    result = None
    for i in range(10):
        result = handle_throughput_request(p, {"throughput": 372.0 + i,
                                                 "mode": "calibrate"})
    check("calibrate mode: response reports mode correctly",
          result["mode"] == "calibrate", f"got {result}")
    check("calibrate mode: after enough samples, the REAL detector "
          "(not a mock) reports calibrated=True",
          p.throughput_contention.calibrated is True,
          f"detector.calibrated={p.throughput_contention.calibrated}")
    check("calibrate mode: response itself reflects the real detector's "
          "calibrated state, not a stale/fabricated value",
          result["calibrated"] is True, f"got {result}")


def test_process_mode_fires_on_real_measured_contention_event():
    p = DetectionPipeline()
    for _ in range(10):
        handle_throughput_request(p, {"throughput": 372.32, "mode": "calibrate"})
    check("calibrated on the real baseline value", p.throughput_contention.calibrated)

    results = [handle_throughput_request(p, {"throughput": 336.96, "mode": "process"})
               for _ in range(5)]
    fired = [r for r in results if r["alert"] is not None]
    check("process mode: fires an alert on the real measured contention "
          "event, reached through the actual API-facing function",
          len(fired) >= 1 and fired[0]["alert"]["type"] == "THROUGHPUT_CONTENTION",
          f"got {results}")


def test_process_mode_silent_on_normal_fluctuation():
    p = DetectionPipeline()
    for _ in range(10):
        handle_throughput_request(p, {"throughput": 372.32, "mode": "calibrate"})

    result = handle_throughput_request(p, {"throughput": 370.0, "mode": "process"})
    check("process mode: silent on normal small fluctuation (~1% dip)",
          result["alert"] is None, f"got {result}")


def test_process_mode_alert_feeds_into_api_state():
    _state['alerts'].clear()
    _state['alert_count'] = 0

    p = DetectionPipeline()
    for _ in range(10):
        handle_throughput_request(p, {"throughput": 372.32, "mode": "calibrate"})
    for _ in range(5):
        handle_throughput_request(p, {"throughput": 336.96, "mode": "process"})

    check("a real throughput alert was pushed into _state['alerts'], "
          "reachable by /alerts and /metrics",
          any(a.get('type') == 'THROUGHPUT_CONTENTION' for a in _state['alerts']),
          f"_state['alerts']={_state['alerts']}")


def test_set_pipeline_updates_module_global():
    import api.server as server_module
    p = DetectionPipeline()
    set_pipeline(p)
    check("set_pipeline: module-level _pipeline reference is updated",
          server_module._pipeline is p)
    set_pipeline(None)


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
