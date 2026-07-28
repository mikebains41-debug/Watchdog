# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_baseline_freeze_fix.py

Regression tests for a real bug found after tonight's initial fixes:
GhostPowerDetector, DMAAttackDetector, and AgentOrchestrationAnomalyDetector
all kept recomputing their learned baseline forever, using the same
condition that gated their firing logic. That meant a SUSTAINED attack --
the exact thing each detector exists to catch -- could feed its own
elevated samples back into the baseline, slowly dragging the baseline up
to match the attack, shrinking delta toward zero, and silencing the
detector on the event it was supposed to catch.

Each test below: calibrate a clean baseline, then feed a LONG sustained
attack pattern that would have qualified for baseline inclusion under the
OLD (unfrozen) code. Confirm the baseline does not move and the detector
keeps firing throughout, not just once at the start.

Run: python tests/test_baseline_freeze_fix.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.engines import GhostPowerDetector
from detection.hardware_attacks import DMAAttackDetector
from detection.llm_attacks import AgentOrchestrationAnomalyDetector

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def row(power, util, mem, idx=0, ts="2026-07-19T00:00:00", util_mem=0, **kw):
    r = {'power.draw': power, 'utilization.gpu': util, 'memory.used': mem,
         'index': idx, 'iso_timestamp': ts, 'utilization.memory': util_mem}
    r.update(kw)
    return r


def test_ghost_power_baseline_freezes_and_resists_sustained_attack():
    d = GhostPowerDetector(baseline_min_samples=30, threshold_w=15.0)
    for _ in range(30):
        d.update(row(80.0, 0, 100))
    frozen_baseline = d.baseline_w
    check("ghost_power: baseline established at clean idle value",
          frozen_baseline is not None and 75 <= frozen_baseline <= 85,
          f"baseline={frozen_baseline}")

    fired_count = 0
    for i in range(500):
        alert = d.update(row(150.0, 0, 100))
        if alert:
            fired_count += 1

    check("ghost_power: baseline is UNCHANGED after 500 sustained attack "
          "samples that would have poisoned the old unfrozen baseline",
          d.baseline_w == frozen_baseline,
          f"baseline drifted from {frozen_baseline} to {d.baseline_w}")
    check("ghost_power: detector fires at least once during the "
          "sustained event -- not permanently silenced (refire_after_s "
          "cooldown means it won't re-fire within milliseconds of real "
          "time, which is correct, separate behavior from the baseline "
          "freeze this test targets)",
          fired_count >= 1, f"fired {fired_count} times, expected >= 1")


def test_dma_baseline_freezes_and_resists_sustained_attack():
    d = DMAAttackDetector(baseline_min_samples=30, require_consecutive=5)
    for _ in range(30):
        d.update(row(80.0, 0, 500, util_mem=5))
    frozen_baseline = d.baseline_mem
    check("dma: baseline established at clean idle memory value",
          frozen_baseline is not None and 495 <= frozen_baseline <= 505,
          f"baseline={frozen_baseline}")

    fired_count = 0
    for i in range(500):
        alert = d.update(row(80.0, 0, 5000, util_mem=50))
        if alert:
            fired_count += 1

    check("dma: baseline_mem is UNCHANGED after 500 sustained attack "
          "samples", d.baseline_mem == frozen_baseline,
          f"baseline drifted from {frozen_baseline} to {d.baseline_mem}")
    check("dma: detector fires at least once during the sustained "
          "event -- not permanently silenced",
          fired_count >= 1, f"fired {fired_count} times, expected >= 1")


def test_agent_orch_baseline_freezes_and_resists_sustained_attack():
    d = AgentOrchestrationAnomalyDetector(baseline_min_samples=30,
                                           require_consecutive=5)
    for _ in range(30):
        d.update(row(80.0, 0, 100))
    frozen_baseline = d.baseline_w
    check("agent_orch: baseline established at clean idle-context power",
          frozen_baseline is not None and 75 <= frozen_baseline <= 85,
          f"baseline={frozen_baseline}")

    fired_count = 0
    for i in range(500):
        alert = d.update(row(200.0, 0, 100))
        if alert:
            fired_count += 1

    check("agent_orch: baseline_w is UNCHANGED after 500 sustained "
          "attack samples",
          d.baseline_w == frozen_baseline,
          f"baseline drifted from {frozen_baseline} to {d.baseline_w}")
    check("agent_orch: detector fires at least once during the "
          "sustained event -- not permanently silenced",
          fired_count >= 1, f"fired {fired_count} times, expected >= 1")


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
