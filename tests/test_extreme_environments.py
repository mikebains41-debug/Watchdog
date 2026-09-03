#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_extreme_environments.py

Tests the radiation-damage layer (SEL latch-up, TID dose), the subsea
integrity layer (hull margin, seawater ingress, cooling degradation), and
the extreme-environment swarm correlator.

Run standalone: python3 tests/test_extreme_environments.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from detection.radiation_damage_detectors import (
    SingleEventLatchupDetector, TotalIonizingDoseAccumulator,
)
from detection.subsea_integrity_detectors import (
    HullPressureMarginMonitor, SeawaterIngressDetector, CoolingDegradationDetector,
    hydrostatic_pressure_pa, critical_buckling_pressure_pa,
)
from intelligence.swarm.extreme_env_swarm_correlator import ExtremeEnvSwarmCorrelator

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


# --------------------------------------------------------------------------
# SEL latch-up
# --------------------------------------------------------------------------
def test_sel_latchup_fires_on_persistent_step_no_util_change():
    sel = SingleEventLatchupDetector(gpu_id=0)
    for _ in range(10):
        sel.update(300.0, 60.0)
    r = None
    for _ in range(6):
        r = sel.update(520.0, 60.0)   # 1.73x, util flat
    check("sel: persistent current step w/ flat util -> SEL_LATCHUP_SUSPECTED",
          r["type"] == "SEL_LATCHUP_SUSPECTED", f"got {r['type']}")
    check("sel: latch-up is CRITICAL + gated power-cycle",
          r["severity"] == "CRITICAL" and r["recommended_action"]["risk"] == "gated", f"got {r}")


def test_sel_legit_burst_not_flagged():
    sel = SingleEventLatchupDetector(gpu_id=0)
    for _ in range(10):
        sel.update(300.0, 30.0)
    r = None
    for _ in range(6):
        r = sel.update(520.0, 95.0)   # power up AND util up = real work
    check("sel: power step WITH util rise -> legitimate burst, not latch-up",
          r["type"] == "POWER_STEP_WITH_WORKLOAD", f"got {r['type']}")


def test_sel_transient_spike_not_flagged():
    sel = SingleEventLatchupDetector(gpu_id=0, persist_samples=5)
    for _ in range(10):
        sel.update(300.0, 60.0)
    sel.update(600.0, 60.0)          # one-sample spike
    r = None
    for _ in range(5):
        r = sel.update(300.0, 60.0)  # returns to baseline
    check("sel: one-sample transient (returns to baseline) -> SEL_NOMINAL",
          r["type"] == "SEL_NOMINAL", f"got {r['type']}")


def test_sel_warming_up():
    sel = SingleEventLatchupDetector(gpu_id=0)
    r = sel.update(300.0, 60.0)
    check("sel: insufficient history -> SEL_WARMING_UP", r["type"] == "SEL_WARMING_UP")


# --------------------------------------------------------------------------
# TID dose
# --------------------------------------------------------------------------
def test_tid_nominal_at_ground_level():
    tid = TotalIonizingDoseAccumulator("gpu0", rated_tolerance_krad=15.0)
    r = None
    for _ in range(100):
        r = tid.accumulate(dose_rate_rad_per_hr=0.0005, dt_hours=24)  # ground-level trickle
    check("tid: ground-level dose stays TID_NOMINAL (honest negative control)",
          r["type"] == "TID_NOMINAL", f"got {r['type']}")


def test_tid_crosses_thresholds_in_order():
    tid = TotalIonizingDoseAccumulator("gpu0", rated_tolerance_krad=15.0,
                                       warn_fractions=(0.5, 0.75, 0.9))
    types = []
    for _ in range(200):
        r = tid.accumulate(dose_rate_rad_per_hr=1.0, dt_hours=100)  # 100 rad per step
        if r["type"] != "TID_NOMINAL":
            types.append((r["type"], r.get("threshold_fraction")))
        if r["type"] == "TID_RATING_EXCEEDED":
            break
    fired = [f for (t, f) in types if t == "TID_THRESHOLD_CROSSED"]
    check("tid: 50%/75%/90% thresholds fire in order",
          fired == [0.5, 0.75, 0.9], f"got {fired}")
    check("tid: rating exceeded fires at 100%",
          any(t == "TID_RATING_EXCEEDED" for (t, _) in types), f"got {types}")


def test_tid_threshold_fires_once():
    tid = TotalIonizingDoseAccumulator("gpu0", rated_tolerance_krad=1.0, warn_fractions=(0.5,))
    r1 = tid.accumulate(600, 1)   # 0.6 krad -> crosses 50%
    r2 = tid.accumulate(10, 1)    # still above 50%, must NOT re-fire
    check("tid: a crossed threshold does not re-fire",
          r1["type"] == "TID_THRESHOLD_CROSSED" and r2["type"] == "TID_NOMINAL",
          f"got {r1['type']}, {r2['type']}")


# --------------------------------------------------------------------------
# Subsea: hull pressure
# --------------------------------------------------------------------------
def test_hydrostatic_pressure_150m():
    p = hydrostatic_pressure_pa(150.0)
    # ~16.1 bar per the spec's worked example
    check("hull: 150m hydrostatic ~16.1 bar", 15.5e5 < p < 16.7e5, f"got {p/1e5:.2f} bar")


def test_buckling_scales_with_cube():
    p1 = critical_buckling_pressure_pa(0.03, 1.5)
    p2 = critical_buckling_pressure_pa(0.015, 1.5)  # half thickness
    check("hull: halving thickness cuts buckling pressure ~8x (cube law)",
          7.5 < p1 / p2 < 8.5, f"ratio {p1/p2:.2f}")


def test_hull_nominal_then_corroded_critical():
    hull = HullPressureMarginMonitor(radius_m=1.5, design_thickness_m=0.05)  # 50mm: 2.5x margin at 150m
    clean = hull.check(150.0)
    corroded = hull.check(150.0, current_thickness_m=0.03)  # 40% thinning -> margin 0.55, crushes
    check("hull: clean at 150m -> HULL_NOMINAL", clean["type"] == "HULL_NOMINAL", f"got {clean}")
    check("hull: heavily corroded -> buckling risk (margin collapses)",
          corroded["type"] in ("HULL_BUCKLING_RISK_CRITICAL", "HULL_MARGIN_LOW")
          and corroded["safety_margin"] < clean["safety_margin"], f"got {corroded}")


# --------------------------------------------------------------------------
# Subsea: ingress
# --------------------------------------------------------------------------
def test_ingress_dry_vessel():
    ing = SeawaterIngressDetector()
    r = None
    for _ in range(5):
        r = ing.update(bilge_level_mm=0.0, internal_temp_c=22.0, dew_point_c=10.0,
                       penetrator_insulation_mohm=1000.0)
    check("ingress: dry, dry-air, good insulation -> VESSEL_DRY", r["type"] == "VESSEL_DRY", f"got {r}")


def test_ingress_single_signal_suspected():
    ing = SeawaterIngressDetector()
    r = None
    for i in range(6):
        r = ing.update(bilge_level_mm=i * 0.6, internal_temp_c=22.0, dew_point_c=10.0,
                       penetrator_insulation_mohm=1000.0)
    check("ingress: bilge rising alone -> INGRESS_SUSPECTED",
          r["type"] == "SEAWATER_INGRESS_SUSPECTED" and "BILGE_RISING" in r["signals"], f"got {r}")


def test_ingress_corroborated_confirmed():
    ing = SeawaterIngressDetector()
    r = None
    for i in range(6):
        r = ing.update(bilge_level_mm=i * 0.6, internal_temp_c=22.0 - i * 0.5,
                       dew_point_c=20.0, penetrator_insulation_mohm=1000 - i * 60)
    check("ingress: 2+ signals -> SEAWATER_INGRESS_CONFIRMED (CRITICAL)",
          r["type"] == "SEAWATER_INGRESS_CONFIRMED" and r["severity"] == "CRITICAL", f"got {r}")


# --------------------------------------------------------------------------
# Subsea: cooling degradation
# --------------------------------------------------------------------------
def test_cooling_requires_baseline():
    cool = CoolingDegradationDetector(hull_area_m2=40.0)
    r = cool.update(200_000, 30.0, 10.0)
    check("cooling: unsealed -> COOLING_UNSEALED", r["type"] == "COOLING_UNSEALED")


def test_cooling_nominal_when_stable():
    cool = CoolingDegradationDetector(hull_area_m2=40.0)
    cool.seal_baseline(200_000, 30.0, 10.0)
    r = None
    for _ in range(5):
        r = cool.update(200_000, 30.0, 10.0)
    check("cooling: same load, same dT -> COOLING_NOMINAL", r["type"] == "COOLING_NOMINAL", f"got {r}")


def test_cooling_fouling_degrades():
    cool = CoolingDegradationDetector(hull_area_m2=40.0)
    cool.seal_baseline(200_000, 30.0, 10.0)   # dT=20
    r = None
    for _ in range(6):
        r = cool.update(200_000, 45.0, 10.0)  # same heat, dT=35 -> U fell ~43%
    check("cooling: same heat needs bigger dT -> COOLING_DEGRADATION_CRITICAL",
          r["type"] == "COOLING_DEGRADATION_CRITICAL", f"got {r}")


# --------------------------------------------------------------------------
# Extreme-env swarm correlator
# --------------------------------------------------------------------------
def test_radiation_degraded_node():
    clock = {"t": 1000.0}
    c = ExtremeEnvSwarmCorrelator(time_fn=lambda: clock["t"])
    check("xenv: SEL alone -> no incident", c.observe({"swarm_signal": "SEL_LATCHUP_SUSPECTED"}) == [])
    clock["t"] += 5
    out = c.observe({"type": "SDC_CORRUPTION_DETECTED"})
    check("xenv: SEL + SDC -> RADIATION_DEGRADED_NODE",
          any(i["incident"] == "RADIATION_DEGRADED_NODE" for i in out), f"got {out}")


def test_latchup_destructive_risk():
    clock = {"t": 2000.0}
    c = ExtremeEnvSwarmCorrelator(time_fn=lambda: clock["t"])
    c.observe({"swarm_signal": "SEL_LATCHUP_SUSPECTED"})
    clock["t"] += 5
    out = c.observe({"type": "THERMAL_EVENT_PREDICTED"})
    check("xenv: SEL + thermal -> LATCHUP_DESTRUCTIVE_RISK",
          any(i["incident"] == "LATCHUP_DESTRUCTIVE_RISK" for i in out), f"got {out}")


def test_subsea_vessel_compromise():
    clock = {"t": 3000.0}
    c = ExtremeEnvSwarmCorrelator(time_fn=lambda: clock["t"])
    c.observe({"swarm_signal": "SEAWATER_INGRESS_CONFIRMED"})
    clock["t"] += 5
    out = c.observe({"swarm_signal": "COOLING_DEGRADATION_WARNING"})
    check("xenv: ingress + cooling -> SUBSEA_VESSEL_COMPROMISE",
          any(i["incident"] == "SUBSEA_VESSEL_COMPROMISE" for i in out), f"got {out}")


def test_cooling_driven_integrity_loss():
    clock = {"t": 4000.0}
    c = ExtremeEnvSwarmCorrelator(time_fn=lambda: clock["t"])
    c.observe({"swarm_signal": "COOLING_DEGRADATION_CRITICAL"})
    clock["t"] += 5
    out = c.observe({"type": "SDC_CORRUPTION_DETECTED"})
    check("xenv: cooling degradation + SDC -> COOLING_DRIVEN_INTEGRITY_LOSS",
          any(i["incident"] == "COOLING_DRIVEN_INTEGRITY_LOSS" for i in out), f"got {out}")


def test_xenv_outside_window():
    clock = {"t": 5000.0}
    c = ExtremeEnvSwarmCorrelator(window_seconds=120.0, time_fn=lambda: clock["t"])
    c.observe({"swarm_signal": "SEL_LATCHUP_SUSPECTED"})
    clock["t"] += 500
    out = c.observe({"type": "SDC_CORRUPTION_DETECTED"})
    check("xenv: signals outside window do not fuse",
          not any(i["incident"] == "RADIATION_DEGRADED_NODE" for i in out), f"got {out}")


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
