#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_sdc_compute_integrity.py

Tests the SDC / compute-integrity suite: Dr. DNA monitor, nullification/
NaN/Inf cascade detector, Freivalds verifier (incl. FP4 honesty gate),
voltage-droop correlator, TMR voter, and the SDC swarm correlator.

Run standalone: python3 tests/test_sdc_compute_integrity.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys
import random

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from detection.sdc_compute_integrity import (
    DrDNAMonitor, NullificationCascadeDetector,
)
from detection.sdc_compute_integrity2 import (
    FreivaldsVerifier, VoltageDroopCorrelator, TMRVoter,
)
from intelligence.swarm.sdc_swarm_correlator import SDCSwarmCorrelator

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
# Dr. DNA monitor
# --------------------------------------------------------------------------
def _clean_profile(seed=1, neurons=5, samples=50):
    random.seed(seed)
    return {i: [random.gauss(0, 1) for _ in range(samples)] for i in range(neurons)}


def test_drdna_requires_profile_first():
    dna = DrDNAMonitor()
    r = dna.check({0: 1.0})
    check("drdna: unprofiled -> DRDNA_SKIPPED",
          r["type"] == "DRDNA_SKIPPED", f"got {r['type']}")


def test_drdna_profiles_and_passes_clean():
    dna = DrDNAMonitor(z_threshold=6.0)
    p = dna.profile(_clean_profile())
    check("drdna: profiling succeeds", p["status"] == "PROFILED", f"got {p}")
    r = dna.check({i: 0.2 for i in range(5)})
    check("drdna: near-mean activations -> COMPUTE_INTEGRITY_OK",
          r["type"] == "COMPUTE_INTEGRITY_OK", f"got {r['type']}")


def test_drdna_flags_deviation():
    dna = DrDNAMonitor(z_threshold=6.0)
    dna.profile(_clean_profile())
    r = dna.check({0: 100.0, 1: 0.1, 2: 0.1, 3: 0.1, 4: 0.1})
    check("drdna: large deviation -> SDC_CORRUPTION_DETECTED",
          r["type"] == "SDC_CORRUPTION_DETECTED", f"got {r['type']}")
    check("drdna: deviation lists the offending neuron",
          any(d["neuron"] == 0 for d in r["deviations"]), f"got {r.get('deviations')}")


def test_drdna_insufficient_profile():
    dna = DrDNAMonitor(min_profile_samples=100)
    p = dna.profile({0: [0.1, 0.2, 0.3]})
    check("drdna: too few profile samples -> PROFILE_INSUFFICIENT",
          p["status"] == "PROFILE_INSUFFICIENT", f"got {p}")


# --------------------------------------------------------------------------
# Nullification / NaN / Inf cascade
# --------------------------------------------------------------------------
def test_nullification_flags_zeroing():
    nc = NullificationCascadeDetector()
    r = nc.check(zero_fraction=0.99)
    check("nullification: high zero-fraction -> SDC_CORRUPTION_DETECTED",
          r["type"] == "SDC_CORRUPTION_DETECTED" and "NULLIFICATION" in r["signals"],
          f"got {r}")


def test_nan_inf_cascade_flagged():
    nc = NullificationCascadeDetector()
    rn = nc.check(zero_fraction=0.1, has_nan=True)
    ri = nc.check(zero_fraction=0.1, has_inf=True)
    check("nullification: NaN -> flagged", "NAN_CASCADE" in rn.get("signals", []), f"got {rn}")
    check("nullification: Inf -> flagged", "INF_CASCADE" in ri.get("signals", []), f"got {ri}")


def test_nullification_fp4_note():
    nc = NullificationCascadeDetector(precision="nvfp4")
    r = nc.check(zero_fraction=0.99)
    check("nullification: FP4 carries micro-block scaling note",
          "fp4_note" in r, f"got keys {list(r.keys())}")


def test_nullification_clean():
    nc = NullificationCascadeDetector()
    r = nc.check(zero_fraction=0.1)
    check("nullification: clean -> COMPUTE_INTEGRITY_OK",
          r["type"] == "COMPUTE_INTEGRITY_OK", f"got {r['type']}")


# --------------------------------------------------------------------------
# Freivalds verifier
# --------------------------------------------------------------------------
def test_freivalds_passes_correct_product():
    fv = FreivaldsVerifier(precision="fp8")
    A = [[1, 2], [3, 4]]; B = [[5, 6], [7, 8]]; C = [[19, 22], [43, 50]]
    r = fv.verify(A, B, C)
    check("freivalds: correct product -> COMPUTE_INTEGRITY_OK",
          r["type"] == "COMPUTE_INTEGRITY_OK", f"got {r['type']}")


def test_freivalds_catches_corrupt_product():
    fv = FreivaldsVerifier(precision="fp8")
    A = [[1, 2], [3, 4]]; B = [[5, 6], [7, 8]]; C = [[19, 22], [43, 99]]
    r = fv.verify(A, B, C)
    check("freivalds: corrupt product -> SDC_CORRUPTION_DETECTED",
          r["type"] == "SDC_CORRUPTION_DETECTED", f"got {r['type']}")


def test_freivalds_fp4_honesty_gate():
    fv = FreivaldsVerifier()
    A = [[1, 2], [3, 4]]; B = [[5, 6], [7, 8]]; C = [[19, 22], [43, 50]]
    r = fv.verify(A, B, C, precision="nvfp4")
    check("freivalds: FP4 -> NOT_APPLICABLE (honesty gate)",
          r["type"] == "FREIVALDS_NOT_APPLICABLE", f"got {r['type']}")


def test_freivalds_tolerates_rounding():
    fv = FreivaldsVerifier(precision="fp8", rel_tolerance=1e-3)
    A = [[1.0, 2.0], [3.0, 4.0]]; B = [[5.0, 6.0], [7.0, 8.0]]
    # tiny rounding-level perturbation must NOT false-positive
    C = [[19.0000001, 22.0], [43.0, 50.0]]
    r = fv.verify(A, B, C)
    check("freivalds: rounding-level noise not flagged (tolerance works)",
          r["type"] == "COMPUTE_INTEGRITY_OK", f"got {r['type']}")


# --------------------------------------------------------------------------
# Voltage-droop correlator
# --------------------------------------------------------------------------
def test_droop_plus_integrity_confirms():
    vd = VoltageDroopCorrelator()
    r = vd.check({"voltage_v": 0.58, "min_operating_v": 0.60}, integrity_flag=True)
    check("droop: droop + integrity flag -> DROOP_INDUCED_SDC_CONFIRMED",
          r["type"] == "DROOP_INDUCED_SDC_CONFIRMED", f"got {r['type']}")
    check("droop: result carries GPU Optimizer link",
          "optimizer_link" in r, "missing optimizer link")


def test_droop_alone_is_warning():
    vd = VoltageDroopCorrelator()
    r = vd.check({"power_watts": 100, "baseline_power_w": 200}, integrity_flag=False)
    check("droop: droop without integrity flag -> DROOP_OBSERVED_NO_CORRUPTION",
          r["type"] == "DROOP_OBSERVED_NO_CORRUPTION", f"got {r['type']}")


def test_droop_nominal():
    vd = VoltageDroopCorrelator()
    r = vd.check({"voltage_v": 0.70, "min_operating_v": 0.60,
                  "power_watts": 300, "baseline_power_w": 300}, integrity_flag=False)
    check("droop: healthy power/voltage -> POWER_INTEGRITY_NOMINAL",
          r["type"] == "POWER_INTEGRITY_NOMINAL", f"got {r['type']}")


# --------------------------------------------------------------------------
# TMR voter
# --------------------------------------------------------------------------
def test_tmr_unanimous():
    r = TMRVoter().vote(42.0, 42.0, 42.0)
    check("tmr: all agree -> TMR_UNANIMOUS", r["type"] == "TMR_UNANIMOUS", f"got {r}")


def test_tmr_catches_divergent_lane():
    r = TMRVoter().vote(42.0, 42.0, 99.0)
    check("tmr: one divergent lane -> SDC_CORRUPTION_DETECTED, lane c",
          r["type"] == "SDC_CORRUPTION_DETECTED" and r["divergent_lane"] == "c"
          and r["result"] == 42.0, f"got {r}")


def test_tmr_no_majority():
    r = TMRVoter().vote(1.0, 2.0, 3.0)
    check("tmr: all differ -> TMR_NO_MAJORITY", r["type"] == "TMR_NO_MAJORITY", f"got {r}")


# --------------------------------------------------------------------------
# SDC swarm correlator
# --------------------------------------------------------------------------
def test_sdc_correlator_degrading_silicon():
    clock = {"t": 1000.0}
    c = SDCSwarmCorrelator(time_fn=lambda: clock["t"])
    out = c.observe({"type": "SDC_CORRUPTION_DETECTED"})
    check("sdc-corr: SDC alone -> no incident yet", out == [], f"got {out}")
    clock["t"] += 3
    out = c.observe({"type": "ECC_BREAK_SUSPECTED"})
    check("sdc-corr: SDC + ECC-break -> DEGRADING_SILICON_INCIDENT",
          len(out) == 1 and out[0]["incident"] == "DEGRADING_SILICON_INCIDENT",
          f"got {out}")


def test_sdc_correlator_droop_confirmed_standalone():
    clock = {"t": 2000.0}
    c = SDCSwarmCorrelator(time_fn=lambda: clock["t"])
    out = c.observe({"type": "DROOP_INDUCED_SDC_CONFIRMED"})
    check("sdc-corr: droop-confirmed fires its own incident",
          len(out) == 1 and out[0]["incident"] == "DROOP_INDUCED_CORRUPTION_CONFIRMED",
          f"got {out}")


def test_sdc_correlator_dedupes():
    clock = {"t": 3000.0}
    c = SDCSwarmCorrelator(time_fn=lambda: clock["t"])
    c.observe({"type": "SDC_CORRUPTION_DETECTED"})
    clock["t"] += 1
    first = c.observe({"type": "THERMAL_EVENT_PREDICTED"})
    clock["t"] += 1
    second = c.observe({"type": "THERMAL_EVENT_PREDICTED"})
    check("sdc-corr: incident de-dupes within window",
          len(first) == 1 and second == [], f"first={first} second={second}")


def test_sdc_correlator_outside_window():
    clock = {"t": 4000.0}
    c = SDCSwarmCorrelator(window_seconds=30.0, time_fn=lambda: clock["t"])
    c.observe({"type": "SDC_CORRUPTION_DETECTED"})
    clock["t"] += 100
    out = c.observe({"type": "ECC_BREAK_SUSPECTED"})
    check("sdc-corr: signals outside window do not correlate", out == [], f"got {out}")


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
