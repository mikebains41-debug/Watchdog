#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_model_integrity.py

Tests the Continuous Model Integrity suite: drift monitor (PSI + metric
decay), risk-tiered model register (E-23 dimensions), revalidation-trigger
engine (tier-scaled, gated/never auto-block), and the regulator evidence
package (hash-chained, tamper-evident).

Run standalone: python3 tests/test_model_integrity.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys
import random

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from detection.model_drift_monitor import (
    ModelDriftMonitor, ModelRiskRegister, population_stability_index, compute_risk_tier,
)
from detection.model_revalidation_engine import (
    RevalidationTriggerEngine, EvidencePackageGenerator,
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


def _outputs(mean, sd=0.1, n=800, seed=1):
    random.seed(seed)
    return [random.gauss(mean, sd) for _ in range(n)]


# --------------------------------------------------------------------------
# Drift monitor
# --------------------------------------------------------------------------
def test_psi_identical_is_zero():
    b = [0.25, 0.25, 0.25, 0.25]
    check("psi: identical distributions -> ~0",
          abs(population_stability_index(b, b)) < 1e-9, f"got {population_stability_index(b, b)}")


def test_psi_shifted_is_large():
    b = [0.7, 0.2, 0.05, 0.05]
    c = [0.05, 0.05, 0.2, 0.7]
    psi = population_stability_index(b, c)
    check("psi: heavily shifted distribution -> > 0.25", psi > 0.25, f"got {psi}")


def test_drift_requires_baseline():
    m = ModelDriftMonitor("m")
    r = m.check([0.5, 0.6])
    check("drift: unsealed -> DRIFT_CHECK_SKIPPED", r["type"] == "DRIFT_CHECK_SKIPPED", f"got {r['type']}")


def test_drift_stable():
    m = ModelDriftMonitor("m")
    m.seal_baseline(_outputs(0.5), baseline_metric=0.92)
    r = m.check(_outputs(0.5, seed=2), current_metric=0.918)
    check("drift: same distribution + same metric -> MODEL_STABLE",
          r["type"] == "MODEL_STABLE", f"got {r['type']} psi={r['psi']}")


def test_drift_distribution_shift_triggers_revalidation():
    m = ModelDriftMonitor("m")
    m.seal_baseline(_outputs(0.5), baseline_metric=0.92)
    r = m.check(_outputs(0.8, seed=3), current_metric=0.92)   # big shift, metric fine
    check("drift: significant distribution shift -> MODEL_REVALIDATION_REQUIRED",
          r["type"] == "MODEL_REVALIDATION_REQUIRED", f"got {r['type']} psi={r['psi']}")
    check("drift: emits MODEL_REVALIDATION_REQUIRED swarm signal",
          r["swarm_signal"] == "MODEL_REVALIDATION_REQUIRED", f"got {r['swarm_signal']}")


def test_drift_metric_decay_triggers_revalidation():
    m = ModelDriftMonitor("m", metric_decay_trigger=0.05)
    m.seal_baseline(_outputs(0.5), baseline_metric=0.9205)
    # the documented research decay: 0.9205 -> 0.8579 (delta -0.0626)
    r = m.check(_outputs(0.5, seed=4), current_metric=0.8579)
    check("drift: documented AUC decay 0.9205->0.8579 -> REVALIDATION_REQUIRED",
          r["type"] == "MODEL_REVALIDATION_REQUIRED" and "PERFORMANCE_DECAY" in r["signals"],
          f"got {r}")


def test_drift_carries_regulatory_clauses():
    m = ModelDriftMonitor("m")
    m.seal_baseline(_outputs(0.5))
    r = m.check(_outputs(0.5, seed=5))
    check("drift: result cites E-23 / SR 26-2 / FDA clauses",
          any("E-23" in c for c in r["regulatory_clause"])
          and any("SR 26-2" in c for c in r["regulatory_clause"]), f"got {r['regulatory_clause']}")


# --------------------------------------------------------------------------
# Risk register
# --------------------------------------------------------------------------
def test_tier_high_on_single_high_dimension():
    check("register: one HIGH dimension -> HIGH tier",
          compute_risk_tier({"autonomy": 1, "data_input_reliability_risk": 1,
                             "customer_impact": 3, "regulatory_risk": 1}) == "HIGH")


def test_tier_low():
    check("register: all low -> LOW tier",
          compute_risk_tier({"autonomy": 1, "data_input_reliability_risk": 1,
                             "customer_impact": 1, "regulatory_risk": 1}) == "LOW")


def test_register_flags_inventory_gaps():
    reg = ModelRiskRegister()
    r = reg.register("m1", {"owner": "x"})  # missing purpose/inputs/methodology/limitations
    check("register: missing required fields -> MODEL_REGISTERED_WITH_GAPS",
          r["type"] == "MODEL_REGISTERED_WITH_GAPS" and "purpose" in r["inventory_gaps"],
          f"got {r}")


def test_register_complete_and_inventory():
    reg = ModelRiskRegister()
    reg.register("m1", {"owner": "a", "purpose": "b", "inputs": "c",
                        "methodology": "d", "limitations": "e"},
                 risk_scores={"autonomy": 3, "data_input_reliability_risk": 1,
                              "customer_impact": 1, "regulatory_risk": 1})
    reg.register("m2", {"owner": "a", "purpose": "b", "inputs": "c",
                        "methodology": "d", "limitations": "e"}, third_party=True)
    inv = reg.inventory()
    check("register: inventory counts models and tiers",
          inv["model_count"] == 2 and "m1" in inv["by_tier"]["HIGH"], f"got {inv}")
    check("register: third-party models tracked (B-10)",
          "m2" in inv["third_party_models"], f"got {inv['third_party_models']}")


# --------------------------------------------------------------------------
# Revalidation trigger engine
# --------------------------------------------------------------------------
def test_trigger_high_tier_fires_on_one_strong_signal():
    reg = ModelRiskRegister()
    reg.register("hi", {"owner": "a", "purpose": "b", "inputs": "c",
                        "methodology": "d", "limitations": "e"},
                 risk_scores={"autonomy": 3, "data_input_reliability_risk": 3,
                              "customer_impact": 3, "regulatory_risk": 3})
    eng = RevalidationTriggerEngine(register=reg)
    r = eng.observe("hi", {"type": "SDC_CORRUPTION_DETECTED"})
    check("trigger: HIGH-tier model fires on one strong signal",
          r["type"] == "REVALIDATION_TRIGGERED" and r["risk_tier"] == "HIGH", f"got {r}")


def test_trigger_low_tier_needs_more():
    reg = ModelRiskRegister()
    reg.register("lo", {"owner": "a", "purpose": "b", "inputs": "c",
                        "methodology": "d", "limitations": "e"},
                 risk_scores={"autonomy": 1, "data_input_reliability_risk": 1,
                              "customer_impact": 1, "regulatory_risk": 1})
    eng = RevalidationTriggerEngine(register=reg)
    r1 = eng.observe("lo", {"type": "MODEL_DRIFT_DETECTED"})  # weight 0.5 < LOW threshold 1.0
    check("trigger: LOW-tier model accumulates on a weak signal (proportionality)",
          r1["type"] == "TRIGGER_ACCUMULATING", f"got {r1}")
    r2 = eng.observe("lo", {"type": "WEIGHT_DRIFT_DETECTED"})  # +1.0 -> fires
    check("trigger: LOW-tier fires once threshold reached",
          r2["type"] == "REVALIDATION_TRIGGERED", f"got {r2}")


def test_trigger_never_autoblocks():
    eng = RevalidationTriggerEngine()
    r = eng.observe("m", {"type": "MODEL_TAMPER_CONFIRMED"})
    check("trigger: recommendation is gated, never auto-block",
          r["recommended_action"]["risk"] == "gated_no_autoblock", f"got {r}")
    check("trigger: gating note states it does not disable the live model",
          "Does NOT auto-block" in r["gating_note"], f"got {r.get('gating_note')}")


def test_trigger_unknown_signal_ignored():
    eng = RevalidationTriggerEngine()
    r = eng.observe("m", {"type": "SOME_UNRELATED_ALERT"})
    check("trigger: unrelated signal -> NO_TRIGGER", r["type"] == "NO_TRIGGER", f"got {r}")


# --------------------------------------------------------------------------
# Evidence package
# --------------------------------------------------------------------------
def _model_entry():
    return {"model_id": "claims-v1", "risk_tier": "HIGH",
            "metadata": {"owner": "risk", "purpose": "claims", "inputs": "text",
                         "methodology": "gbm", "limitations": "rare events"},
            "risk_scores": {}, "third_party": False, "inventory_gaps": []}


def test_evidence_package_builds_and_chains():
    gen = EvidencePackageGenerator()
    m = ModelDriftMonitor("claims-v1")
    m.seal_baseline(_outputs(0.5), 0.92)
    drift = [m.check(_outputs(0.5, seed=6), 0.91)]
    pkg = gen.build(_model_entry(), drift_results=drift,
                    integrity_events=[{"type": "SDC_CORRUPTION_DETECTED", "severity": "CRITICAL",
                                       "timestamp": "t"}],
                    framing="fda")
    check("evidence: package builds with 4 hash-chained sections",
          pkg["type"] == "REGULATOR_EVIDENCE_PACKAGE" and len(pkg["sections"]) == 4, f"got {pkg}")
    check("evidence: hash chain verifies", EvidencePackageGenerator.verify_chain(pkg), "chain invalid")
    check("evidence: attestation counts the open finding",
          pkg["attestation_rollup"]["open_findings"] == 1, f"got {pkg['attestation_rollup']}")


def test_evidence_tamper_breaks_chain():
    gen = EvidencePackageGenerator()
    pkg = gen.build(_model_entry(), drift_results=[], integrity_events=[], framing="e23")
    # tamper with a section's content after the fact
    pkg["sections"][0]["content"]["owner"] = "attacker"
    check("evidence: editing a section breaks the hash chain (tamper-evident)",
          not EvidencePackageGenerator.verify_chain(pkg), "chain should be invalid")


def test_evidence_framings():
    gen = EvidencePackageGenerator()
    fda = gen.build(_model_entry(), [], [], framing="fda")
    e23 = gen.build(_model_entry(), [], [], framing="e23")
    check("evidence: FDA framing cites 21 CFR Part 11",
          any("21 CFR Part 11" in m for m in fda["regulatory_mapping"]), f"got {fda['regulatory_mapping']}")
    check("evidence: E-23 framing cites OSFI E-23 / SR 26-2",
          any("E-23" in m for m in e23["regulatory_mapping"]), f"got {e23['regulatory_mapping']}")


def test_evidence_not_legal_advice():
    gen = EvidencePackageGenerator()
    pkg = gen.build(_model_entry(), [], [], framing="fda")
    check("evidence: package states not-legal-advice / evidence-not-compliance",
          "Not legal advice" in pkg["note"], f"got {pkg['note']}")


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
