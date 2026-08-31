#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_validation_harness.py

Tests the on-pod validation harness with the FAKE backend (no GPU): that
each stage runs, labels its confidence tier correctly, that Tier-1 requires
BOTH a fire-on-attack and silence-on-clean, that Tier-2 is capability-only,
and that Tier-3 is recorded-not-attempted.

Run standalone: python3 tests/test_validation_harness.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from runtime.validation_harness import (
    ValidationHarness, FakeBackend, TIER1, TIER2, TIER3,
)

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


# detector hooks that mirror real detector behavior
GOOD_HOOKS = {
    "cryptojacking_onset": lambda e: e.get("util_pct", 0) > 90 and e.get("sm_clock_uniform", False),
    "nvlink_contention": lambda e: e.get("nvlink_kb_per_s", 0) > 1_000_000,
    "ghost_power": lambda e: e.get("ghost_watts", 0) > 5,
    "sdc_drdna": lambda e: any(abs(v) > 10 for v in e.values() if isinstance(v, (int, float))),
    "rowhammer_precursor": lambda e: False,
}


def _harness(gpu_count=4, hooks=None):
    return ValidationHarness(FakeBackend(gpu_count=gpu_count),
                             detector_hooks=hooks if hooks is not None else GOOD_HOOKS)


# --------------------------------------------------------------------------
# Tier-1 true positives
# --------------------------------------------------------------------------
def test_covert_compute_true_positive():
    h = _harness()
    r = h.stage_covert_compute()
    check("harness: covert-compute is Tier1 and passes (fire+silent)",
          r["tier"] == TIER1 and r["passed"], f"got {r}")


def test_covert_compute_fails_without_negative_control():
    # a hook that fires on EVERYTHING should FAIL the stage (no negative control)
    bad = dict(GOOD_HOOKS)
    bad["cryptojacking_onset"] = lambda e: True
    h = _harness(hooks=bad)
    r = h.stage_covert_compute()
    check("harness: fires-on-everything FAILS (negative control enforced)",
          r["tier"] == TIER1 and not r["passed"], f"got {r}")


def test_nvlink_true_positive():
    h = _harness()
    r = h.stage_nvlink()
    check("harness: nvlink live-fire Tier1 passes on multi-GPU",
          r["tier"] == TIER1 and r["passed"], f"got {r}")


def test_nvlink_single_gpu_is_tier3():
    h = _harness(gpu_count=1)
    r = h.stage_nvlink()
    check("harness: nvlink on 1 GPU -> Tier3 cannot-induce",
          r["tier"] == TIER3, f"got {r}")


def test_vram_cross_process_read_true_positive():
    h = _harness()
    r = h.stage_vram_residual()
    check("harness: VRAM cross-process read is Tier1 and finds the pattern",
          r["tier"] == TIER1 and r["passed"], f"got {r}")
    check("harness: VRAM stage note clarifies self-owned, not an attack",
          "self-owned" in r["note"], f"got {r['note']}")


def test_cross_gpu_residual_runs():
    h = _harness()
    r = h.stage_cross_gpu_residual()
    check("harness: cross-GPU residual is Tier1 and produces a result",
          r["tier"] == TIER1 and r["passed"], f"got {r}")


def test_cross_gpu_residual_single_gpu_tier3():
    h = _harness(gpu_count=1)
    r = h.stage_cross_gpu_residual()
    check("harness: cross-GPU residual on 1 GPU -> Tier3",
          r["tier"] == TIER3, f"got {r}")


def test_ghost_power_true_positive():
    h = _harness()
    r = h.stage_ghost_power()
    check("harness: ghost power Tier1 passes (floor above true idle)",
          r["tier"] == TIER1 and r["passed"], f"got {r}")


def test_sdc_drdna_true_positive():
    h = _harness()
    r = h.stage_sdc_drdna()
    check("harness: SDC/Dr.DNA Tier1 passes (fires on corrupt, silent on clean)",
          r["tier"] == TIER1 and r["passed"], f"got {r}")


# --------------------------------------------------------------------------
# Tier-2 capability check (Rowhammer)
# --------------------------------------------------------------------------
def test_rowhammer_is_capability_tier2():
    h = _harness()
    r = h.stage_rowhammer_capability()
    check("harness: rowhammer is Tier2 capability (not Tier1)",
          r["tier"] == TIER2, f"got {r}")
    check("harness: rowhammer passes capability (ECC present + silent on clean)",
          r["passed"], f"got {r}")
    check("harness: rowhammer note states true-positive needs owned hardware",
          "owned bare-metal" in r["note"], f"got {r['note']}")


# --------------------------------------------------------------------------
# Tier-3 cannot-induce
# --------------------------------------------------------------------------
def test_quantum_is_tier3():
    h = _harness()
    r = h.stage_quantum_note()
    check("harness: quantum is Tier3 cannot-induce-here",
          r["tier"] == TIER3 and not r["passed"], f"got {r}")


# --------------------------------------------------------------------------
# Full run + summary
# --------------------------------------------------------------------------
def test_run_all_summary():
    h = _harness()
    s = h.run_all()
    check("harness: run_all produces a VALIDATION_SUMMARY",
          s["type"] == "VALIDATION_SUMMARY", f"got {s.get('type')}")
    check("harness: multiple Tier-1 true-positives pass",
          s["tier1_true_positive"]["passed"] >= 5, f"got {s['tier1_true_positive']}")
    check("harness: rowhammer listed under Tier-2 capability",
          "rowhammer_capability" in s["tier2_capability"], f"got {s['tier2_capability']}")
    check("harness: quantum listed under Tier-3 cannot-induce",
          "quantum_control_plane" in s["tier3_cannot_induce"], f"got {s['tier3_cannot_induce']}")
    check("harness: summary carries the tier-labeling honesty note",
          "Only Tier-1 may drop" in s["note"], f"got {s['note']}")


def test_unknown_detector_hook_does_not_crash():
    # no hooks at all -> stages that depend on a fire result won't PASS, but
    # the harness must not crash and must still record every stage.
    h = ValidationHarness(FakeBackend(gpu_count=4), detector_hooks={})
    s = h.run_all()
    check("harness: runs with no detector hooks, records all stages",
          s["stages_total"] == 8, f"got {s['stages_total']}")


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
