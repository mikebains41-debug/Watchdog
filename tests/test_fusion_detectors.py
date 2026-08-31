#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_fusion_detectors.py

Tests the cross-layer fusion detectors (GPU/CPU/quantum) and the
cross-layer correlator. The differentiator cases are the important ones:
a clean file with a hardware mismatch, a benign prompt with a physical
anomaly, and the swarm fusing software + physical signals into one incident.

Run standalone: python3 tests/test_fusion_detectors.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from detection.fusion_detectors import (
    ModelScanHardwareFusion, PromptInjectionPhysicalFusion, GPU, CPU, QUANTUM,
)
from detection.fusion_capabilities import (
    HardwareRedTeamHarness, UnifiedAssetDiscovery, HardwareThreatIntelFeed,
)
from intelligence.swarm.cross_layer_correlator import CrossLayerCorrelator

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
# Detector 1 -- model-scan + hardware fusion (the differentiator case)
# --------------------------------------------------------------------------
def test_clean_file_hardware_mismatch_is_the_differentiator():
    m = ModelScanHardwareFusion(substrate=GPU)
    r = m.evaluate({"clean": True, "flags": []},
                   declared={"expected_vram_mb": 8000, "expected_power_w": 300},
                   observed={"observed_vram_mb": 8100, "observed_power_w": 470})
    check("fusion1: clean file + hardware mismatch -> MODEL_TAMPER_HARDWARE_MISMATCH",
          r["type"] == "MODEL_TAMPER_HARDWARE_MISMATCH", f"got {r['type']}")
    check("fusion1: differentiator note present",
          "differentiator_note" in r, "missing")


def test_clean_file_matching_hardware_ok():
    m = ModelScanHardwareFusion(substrate=GPU)
    r = m.evaluate({"clean": True, "flags": []},
                   declared={"expected_vram_mb": 8000, "expected_power_w": 300},
                   observed={"observed_vram_mb": 8050, "observed_power_w": 305})
    check("fusion1: clean file + matching hardware -> MODEL_INTEGRITY_OK",
          r["type"] == "MODEL_INTEGRITY_OK", f"got {r['type']}")


def test_flagged_file_plus_mismatch_confirmed():
    m = ModelScanHardwareFusion(substrate=GPU)
    r = m.evaluate({"clean": False, "flags": ["pickle"]},
                   declared={"expected_power_w": 300},
                   observed={"observed_power_w": 500})
    check("fusion1: flagged file + mismatch -> MODEL_TAMPER_CONFIRMED",
          r["type"] == "MODEL_TAMPER_CONFIRMED", f"got {r['type']}")


def test_cpu_uses_compute_time_not_power():
    m = ModelScanHardwareFusion(substrate=CPU)
    r = m.evaluate({"clean": True},
                   declared={"expected_compute_ms": 100},
                   observed={"observed_compute_ms": 180})
    check("fusion1: CPU substrate uses compute-time corroborator",
          r["type"] == "MODEL_TAMPER_HARDWARE_MISMATCH"
          and r["hardware_mismatches"][0]["dimension"] == "compute_time",
          f"got {r}")


def test_quantum_uses_circuit_depth():
    m = ModelScanHardwareFusion(substrate=QUANTUM)
    r = m.evaluate({"clean": True},
                   declared={"expected_depth": 20},
                   observed={"observed_depth": 35})
    check("fusion1: quantum substrate uses circuit-depth corroborator",
          r["hardware_mismatches"][0]["dimension"] == "circuit_depth", f"got {r}")


# --------------------------------------------------------------------------
# Detector 2 -- prompt injection + physical fusion
# --------------------------------------------------------------------------
def test_benign_text_power_spike_caught_by_physics():
    p = PromptInjectionPhysicalFusion(substrate=GPU)
    r = p.evaluate({"suspicious": False, "reason": "clean"},
                   {"power_watts": 320, "baseline_power_w": 194})
    check("fusion2: benign text + power spike -> PROMPT_PHYSICAL_ANOMALY",
          r["type"] == "PROMPT_PHYSICAL_ANOMALY", f"got {r['type']}")
    check("fusion2: differentiator note on physics-caught injection",
          "differentiator_note" in r, "missing")


def test_suspicious_text_and_spike_confirmed():
    p = PromptInjectionPhysicalFusion(substrate=GPU)
    r = p.evaluate({"suspicious": True, "reason": "ignore-instructions"},
                   {"power_watts": 340, "baseline_power_w": 194})
    check("fusion2: suspicious text + spike -> PHYSICALLY_CONFIRMED",
          r["type"] == "PROMPT_INJECTION_PHYSICALLY_CONFIRMED"
          and r["confidence"] == "high", f"got {r}")


def test_suspicious_text_no_spike_only_suspected():
    p = PromptInjectionPhysicalFusion(substrate=GPU)
    r = p.evaluate({"suspicious": True, "reason": "maybe"},
                   {"power_watts": 200, "baseline_power_w": 194})
    check("fusion2: suspicious text, no spike -> SUSPECTED (their level)",
          r["type"] == "PROMPT_INJECTION_SUSPECTED", f"got {r['type']}")


def test_clean_both_is_clean():
    p = PromptInjectionPhysicalFusion(substrate=GPU)
    r = p.evaluate({"suspicious": False}, {"power_watts": 196, "baseline_power_w": 194})
    check("fusion2: clean text + no spike -> PROMPT_CLEAN",
          r["type"] == "PROMPT_CLEAN", f"got {r['type']}")


def test_cpu_context_switch_corroborator():
    p = PromptInjectionPhysicalFusion(substrate=CPU)
    r = p.evaluate({"suspicious": True, "reason": "x"},
                   {"ctx_switches": 90000, "baseline_ctx": 30000})
    check("fusion2: CPU ctx-switch spike confirms",
          r["type"] == "PROMPT_INJECTION_PHYSICALLY_CONFIRMED", f"got {r}")


def test_quantum_fidelity_corroborator():
    p = PromptInjectionPhysicalFusion(substrate=QUANTUM)
    r = p.evaluate({"suspicious": True, "reason": "job param"},
                   {"circuit_fidelity": 0.70, "expected_fidelity": 0.95})
    check("fusion2: quantum fidelity drop confirms job tamper",
          r["type"] == "PROMPT_INJECTION_PHYSICALLY_CONFIRMED", f"got {r}")


def test_missing_physical_is_honest_partial():
    p = PromptInjectionPhysicalFusion(substrate=GPU)
    r = p.evaluate({"suspicious": True, "reason": "x"}, {})  # no power data
    check("fusion2: missing physical data -> honest low-confidence fallback",
          r["confidence"] == "low" and "unavailable" in r.get("note", ""), f"got {r}")


# --------------------------------------------------------------------------
# Detector 3 -- hardware red-team harness
# --------------------------------------------------------------------------
def test_redteam_gpu_scenarios():
    h = HardwareRedTeamHarness(GPU)
    r = h.run()
    check("fusion3: GPU red-team enumerates hardware scenarios",
          r["scenarios_total"] >= 4 and r["coverage_pct"] == 100.0, f"got {r}")


def test_redteam_quantum_scenarios():
    h = HardwareRedTeamHarness(QUANTUM)
    scenarios = h.list_scenarios()
    check("fusion3: quantum red-team includes CHSH tamper check",
          any(s["id"] == "chsh_violation_fail" for s in scenarios), f"got {scenarios}")


def test_redteam_reports_uncovered():
    h = HardwareRedTeamHarness(GPU)
    # simulate one detector NOT firing
    r = h.run(detector_fn=lambda sc: sc["id"] != "ghost_power")
    check("fusion3: uncovered scenario lowers coverage honestly",
          r["coverage_pct"] < 100.0, f"got {r['coverage_pct']}")


# --------------------------------------------------------------------------
# Detector 4 -- unified discovery
# --------------------------------------------------------------------------
def test_discovery_ties_model_to_substrate_and_compliance():
    d = UnifiedAssetDiscovery()
    d.register_asset("fraud-model", GPU, "eu-west", "safetensors", ["EU"])
    d.register_asset("triage-model", QUANTUM, "us-east", None, [])
    inv = d.inventory()
    check("fusion4: inventory counts assets across substrates",
          inv["asset_count"] == 2 and inv["by_substrate"][GPU] == 1, f"got {inv}")
    check("fusion4: flags compliance gap for uncovered asset",
          "triage-model" in inv["compliance_gaps"], f"got {inv['compliance_gaps']}")


# --------------------------------------------------------------------------
# Detector 5 -- hardware threat intel feed
# --------------------------------------------------------------------------
def test_intel_feed_matches_gpu_asset():
    feed = HardwareThreatIntelFeed()
    m = feed.match_asset(GPU, ["h200", "gddr6"])
    check("fusion5: GPU asset matches GPUThor/GPUHammer",
          any(x["id"] == "GPUThor-2026" for x in m["matches"]), f"got {m}")


def test_intel_feed_quantum_threats():
    feed = HardwareThreatIntelFeed()
    m = feed.match_asset(QUANTUM, ["qpu"])
    check("fusion5: quantum asset matches crosstalk threats",
          m["match_count"] >= 1, f"got {m}")


# --------------------------------------------------------------------------
# Cross-layer correlator -- the swarm fusing layers
# --------------------------------------------------------------------------
def test_cross_layer_confirmed_injection_campaign():
    clock = {"t": 1000.0}
    c = CrossLayerCorrelator(time_fn=lambda: clock["t"])
    out = c.observe({"type": "PROMPT_INJECTION_PHYSICALLY_CONFIRMED"})
    check("cross-layer: physical-confirmed injection alone -> no incident yet",
          out == [], f"got {out}")
    clock["t"] += 3
    out = c.observe({"type": "MODEL_TAMPER_CONFIRMED"})
    check("cross-layer: + model tamper -> CONFIRMED_INJECTION_CAMPAIGN",
          len(out) == 1 and out[0]["incident"] == "CONFIRMED_INJECTION_CAMPAIGN",
          f"got {out}")
    check("cross-layer: incident is CRITICAL with differentiator note",
          out[0]["severity"] == "CRITICAL" and "differentiator_note" in out[0], f"got {out}")


def test_cross_layer_stealth_model_swap():
    clock = {"t": 2000.0}
    c = CrossLayerCorrelator(time_fn=lambda: clock["t"])
    c.observe({"type": "MODEL_TAMPER_HARDWARE_MISMATCH"})
    clock["t"] += 2
    out = c.observe({"type": "GPUTHOR_PRECURSOR_PREDICTED"})
    check("cross-layer: hardware-mismatch + ECC precursor -> STEALTH_MODEL_SWAP",
          len(out) == 1 and out[0]["incident"] == "STEALTH_MODEL_SWAP", f"got {out}")


def test_cross_layer_outside_window_no_incident():
    clock = {"t": 3000.0}
    c = CrossLayerCorrelator(window_seconds=30.0, time_fn=lambda: clock["t"])
    c.observe({"type": "PROMPT_INJECTION_PHYSICALLY_CONFIRMED"})
    clock["t"] += 100
    out = c.observe({"type": "MODEL_TAMPER_CONFIRMED"})
    check("cross-layer: signals outside window do not fuse",
          out == [], f"got {out}")


def test_cross_layer_dedupes():
    clock = {"t": 4000.0}
    c = CrossLayerCorrelator(time_fn=lambda: clock["t"])
    c.observe({"type": "PROMPT_INJECTION_PHYSICALLY_CONFIRMED"})
    clock["t"] += 1
    first = c.observe({"type": "MODEL_TAMPER_CONFIRMED"})
    clock["t"] += 1
    second = c.observe({"type": "MODEL_TAMPER_CONFIRMED"})
    check("cross-layer: same incident does not re-fire in window",
          len(first) == 1 and second == [], f"first={first} second={second}")


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
