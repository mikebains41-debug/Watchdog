#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_unified_correlator.py

Tests the unified swarm correlation layer: that it composes sub-correlators
(their alerts keep flowing) AND adds cross-suite incidents that no single
sub-correlator could produce.

Run standalone: python3 tests/test_unified_correlator.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from intelligence.swarm.unified_correlator import UnifiedCorrelator

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


class _FakeSub:
    """Fake sub-correlator: records what it sees, optionally emits an incident."""
    def __init__(self, emit_on=None, incident_name="SUB_INCIDENT"):
        self.seen = []
        self.emit_on = emit_on
        self.incident_name = incident_name
    def observe(self, alert):
        self.seen.append(alert.get("type"))
        if self.emit_on and alert.get("type") == self.emit_on:
            return [{"type": "SUB", "incident": self.incident_name}]
        return []


# --------------------------------------------------------------------------
# Composition: sub-correlators still work
# --------------------------------------------------------------------------
def test_forwards_to_subcorrelators():
    sub = _FakeSub()
    u = UnifiedCorrelator(sub_correlators=[sub])
    u.observe({"type": "SDC_CORRUPTION_DETECTED"})
    u.observe({"type": "ECC_BREAK_SUSPECTED"})
    check("unified: forwards every alert to sub-correlators",
          sub.seen == ["SDC_CORRUPTION_DETECTED", "ECC_BREAK_SUSPECTED"], f"got {sub.seen}")


def test_subcorrelator_incidents_pass_through():
    sub = _FakeSub(emit_on="MICRO_BURST_PATTERN", incident_name="SUB_X")
    u = UnifiedCorrelator(sub_correlators=[sub])
    out = u.observe({"type": "MICRO_BURST_PATTERN"})
    check("unified: sub-correlator incident passes through",
          any(i.get("incident") == "SUB_X" for i in out), f"got {out}")


# --------------------------------------------------------------------------
# Cross-suite rules
# --------------------------------------------------------------------------
def test_catastrophic_node_degradation():
    clock = {"t": 1000.0}
    u = UnifiedCorrelator(time_fn=lambda: clock["t"])
    check("unified: SDC alone -> no cross-suite incident",
          u.observe({"type": "SDC_CORRUPTION_DETECTED"}) == [], "fired too early")
    clock["t"] += 2
    u.observe({"type": "ECC_BREAK_SUSPECTED"})
    clock["t"] += 2
    out = u.observe({"type": "THERMAL_EVENT_PREDICTED"})
    names = [i["incident"] for i in out]
    check("unified: SDC + ECC + thermal -> CATASTROPHIC_NODE_DEGRADATION",
          "CATASTROPHIC_NODE_DEGRADATION" in names, f"got {names}")


def test_compute_under_attack():
    clock = {"t": 2000.0}
    u = UnifiedCorrelator(time_fn=lambda: clock["t"])
    u.observe({"type": "SDC_CORRUPTION_DETECTED"})
    clock["t"] += 2
    out = u.observe({"type": "COVERT_COMPUTE_ONSET_PREDICTED"})
    names = [i["incident"] for i in out]
    check("unified: SDC + covert-compute -> COMPUTE_UNDER_ATTACK",
          "COMPUTE_UNDER_ATTACK" in names, f"got {names}")


def test_quantum_classical_coordinated():
    clock = {"t": 3000.0}
    u = UnifiedCorrelator(time_fn=lambda: clock["t"])
    u.observe({"type": "QUANTUM_CIRCUIT_TAMPER"})
    clock["t"] += 2
    out = u.observe({"type": "SDC_CORRUPTION_DETECTED"})
    names = [i["incident"] for i in out]
    check("unified: quantum tamper + classical SDC -> QUANTUM_CLASSICAL_COORDINATED",
          "QUANTUM_CLASSICAL_COORDINATED" in names, f"got {names}")


def test_full_stack_incident():
    clock = {"t": 4000.0}
    u = UnifiedCorrelator(full_stack_suite_threshold=3, time_fn=lambda: clock["t"])
    # three DISTINCT suites: sdc, quantum, security
    u.observe({"type": "SDC_CORRUPTION_DETECTED"})       # sdc
    clock["t"] += 1
    u.observe({"type": "QUANTUM_CIRCUIT_TAMPER"})        # quantum
    clock["t"] += 1
    out = u.observe({"type": "MODEL_EXTRACTION_PRECURSOR_PREDICTED"})  # security
    names = [i["incident"] for i in out]
    check("unified: 3+ distinct suites -> FULL_STACK_INCIDENT",
          "FULL_STACK_INCIDENT" in names, f"got {names}")
    fs = [i for i in out if i.get("incident") == "FULL_STACK_INCIDENT"]
    check("unified: full-stack incident lists the involved suites",
          fs and len(fs[0]["suites_involved"]) >= 3, f"got {fs}")


# --------------------------------------------------------------------------
# Discipline: window + dedup
# --------------------------------------------------------------------------
def test_cross_suite_outside_window():
    clock = {"t": 5000.0}
    u = UnifiedCorrelator(window_seconds=30.0, time_fn=lambda: clock["t"])
    u.observe({"type": "SDC_CORRUPTION_DETECTED"})
    clock["t"] += 100
    out = u.observe({"type": "COVERT_COMPUTE_ONSET_PREDICTED"})
    names = [i["incident"] for i in out]
    check("unified: signals outside window do not fuse",
          "COMPUTE_UNDER_ATTACK" not in names, f"got {names}")


def test_cross_suite_dedup():
    clock = {"t": 6000.0}
    u = UnifiedCorrelator(time_fn=lambda: clock["t"])
    u.observe({"type": "SDC_CORRUPTION_DETECTED"})
    clock["t"] += 1
    first = u.observe({"type": "COVERT_COMPUTE_ONSET_PREDICTED"})
    clock["t"] += 1
    second = u.observe({"type": "COVERT_COMPUTE_ONSET_PREDICTED"})
    check("unified: cross-suite incident de-dupes within window",
          any(i.get("incident") == "COMPUTE_UNDER_ATTACK" for i in first)
          and not any(i.get("incident") == "COMPUTE_UNDER_ATTACK" for i in second),
          f"first={[i.get('incident') for i in first]} second={[i.get('incident') for i in second]}")


def test_sub_correlator_exception_isolated():
    class _BoomSub:
        def observe(self, alert):
            raise RuntimeError("sub blew up")
    u = UnifiedCorrelator(sub_correlators=[_BoomSub()])
    # must not raise; unified rules still evaluate
    out = u.observe({"type": "SDC_CORRUPTION_DETECTED"})
    check("unified: a broken sub-correlator does not crash the unified layer",
          isinstance(out, list), "raised or returned non-list")


def test_stats_report():
    u = UnifiedCorrelator()
    u.observe({"type": "SDC_CORRUPTION_DETECTED"})
    s = u.get_stats()
    check("unified: stats expose cross-suite rules",
          "FULL_STACK_INCIDENT" in s["cross_suite_rules"], f"got {s}")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
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
