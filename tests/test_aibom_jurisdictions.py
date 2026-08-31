#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_aibom_jurisdictions.py

Tests the multi-jurisdiction AIBOM compliance profile layer: per-component
and fleet-wide checks across EU, US (NIST/CISA/OMB), China, Singapore,
ISO 42001, and Canada.

Run standalone: python3 tests/test_aibom_jurisdictions.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from detection.aibom_jurisdiction_profiles import (
    check_component, check_aibom, JURISDICTION_REQUIRED_FIELDS, ALL_JURISDICTIONS,
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


# fully-specified metadata satisfying EVERY jurisdiction
FULL_META = {
    "license": "Apache-2.0", "training_data": "corpus-v1",
    "intended_purpose": "gpu anomaly detection", "provider": "GPU Optimizer Inc.",
    "risk_classification": "limited",
    "performance_metrics": "f1=0.9", "limitations": "documented",
    "bias_evaluation": "completed", "source": "https://huggingface.co/x",
    "version": "1.0", "sha256": "abc", "timestamp": "2026-08-31T00:00:00Z",
    "acceptable_use_policy": "AUP-v1", "model_card": "card-v1",
    "safety_filters": "enabled",
    "provider_code": "CN-PROV-001", "content_id": "CID-001",
    "generation_timestamp": "2026-08-31T00:00:00Z",
    "cac_filing_number": "CAC-2026-1234", "content_labels": "explicit+implicit",
    "owner": "mike", "change_control": "git",
    "capability_summary": "detects x", "risk_summary": "low",
    "mitigation_summary": "gated",
}


def test_all_jurisdictions_defined():
    expected = {"EU", "US_NIST", "US_CISA", "US_OMB", "CHINA",
                "SINGAPORE", "ISO_42001", "CANADA"}
    check("jurisdictions: all seven+ regions defined including Canada",
          set(ALL_JURISDICTIONS) == expected, f"got {set(ALL_JURISDICTIONS)}")


def test_full_metadata_satisfies_all():
    r = check_component("m.safetensors", FULL_META)
    check("component: fully-specified metadata satisfies every jurisdiction",
          set(r["satisfied_jurisdictions"]) == set(ALL_JURISDICTIONS),
          f"missing {set(ALL_JURISDICTIONS) - set(r['satisfied_jurisdictions'])}")


def test_eu_compliant_but_china_gap():
    """A model with EU fields but no China provider_code/filing must PASS EU
    and FAIL China -- the whole point of the layer."""
    eu_only = {
        "license": "Apache-2.0", "training_data": "corpus",
        "intended_purpose": "x", "provider": "GPU Optimizer Inc.",
        "risk_classification": "limited",
    }
    r = check_component("m.safetensors", eu_only)
    check("component: EU satisfied with EU-only fields",
          "EU" in r["satisfied_jurisdictions"], f"got {r['satisfied_jurisdictions']}")
    check("component: China NOT satisfied without provider_code/filing",
          "CHINA" not in r["satisfied_jurisdictions"], f"got {r['satisfied_jurisdictions']}")
    china = r["per_jurisdiction"]["CHINA"]
    check("component: China gap lists the missing filing fields",
          "cac_filing_number" in china["missing_fields"]
          and "provider_code" in china["missing_fields"], f"got {china}")


def test_china_note_flags_no_eu_mapping():
    r = check_component("m.safetensors", {})
    china = r["per_jurisdiction"]["CHINA"]
    check("component: China result carries the 'does not satisfy EU Art.50' note",
          "note" in china and "EU" in china["note"], f"got {china}")


def test_omb_scope_flagged():
    r = check_component("m.safetensors", {})
    omb = r["per_jurisdiction"]["US_OMB"]
    check("component: US_OMB flagged as federal-procurement scope",
          omb.get("scope") == "US federal procurement only", f"got {omb}")


def test_canada_voluntary_note():
    r = check_component("m.safetensors", {})
    ca = r["per_jurisdiction"]["CANADA"]
    check("component: Canada flagged non-binding with AIDA note",
          ca["binding"] is False and "AIDA" in ca.get("note", ""), f"got {ca}")


def test_binding_flags_correct():
    check("jurisdictions: EU is binding",
          JURISDICTION_REQUIRED_FIELDS["EU"]["binding"] is True)
    check("jurisdictions: China is binding",
          JURISDICTION_REQUIRED_FIELDS["CHINA"]["binding"] is True)
    check("jurisdictions: NIST is voluntary",
          JURISDICTION_REQUIRED_FIELDS["US_NIST"]["binding"] is False)
    check("jurisdictions: Canada is voluntary",
          JURISDICTION_REQUIRED_FIELDS["CANADA"]["binding"] is False)


def test_check_aibom_fleet_rollup():
    # Simulate a build_aibom result with two components.
    aibom_result = {
        "aibom": {
            "components": [
                {"name": "good.safetensors", "version": "1.0",
                 "hashes": [{"alg": "SHA-256", "content": "abc"}]},
                {"name": "bad.safetensors", "version": "UNPINNED",
                 "hashes": [{"alg": "SHA-256", "content": "def"}]},
            ]
        }
    }
    manifest = {"good.safetensors": FULL_META, "bad.safetensors": {}}
    r = check_aibom(aibom_result, manifest=manifest)
    check("fleet: reports per-jurisdiction satisfied counts",
          r["summary_by_jurisdiction"]["EU"]["components_total"] == 2, f"got {r['summary_by_jurisdiction']['EU']}")
    check("fleet: EU has exactly 1 of 2 components compliant (good, not bad)",
          r["summary_by_jurisdiction"]["EU"]["components_satisfied"] == 1,
          f"got {r['summary_by_jurisdiction']['EU']}")
    check("fleet: status is JURISDICTION_GAPS_FOUND (not all compliant)",
          r["status"] == "JURISDICTION_GAPS_FOUND", f"got {r['status']}")


def test_check_aibom_all_compliant():
    aibom_result = {
        "aibom": {"components": [
            {"name": "m.safetensors", "version": "1.0",
             "hashes": [{"alg": "SHA-256", "content": "abc"}]}]}
    }
    manifest = {"m.safetensors": FULL_META}
    r = check_aibom(aibom_result, manifest=manifest)
    check("fleet: all-compliant component -> MULTI_JURISDICTION_COMPLIANT",
          r["status"] == "MULTI_JURISDICTION_COMPLIANT", f"got {r['status']}")
    check("fleet: every jurisdiction listed as fully compliant",
          set(r["fully_compliant_jurisdictions"]) == set(ALL_JURISDICTIONS),
          f"got {r['fully_compliant_jurisdictions']}")


def test_result_carries_not_legal_advice_note():
    r = check_aibom({"aibom": {"components": []}}, manifest={})
    check("fleet: result states NOT legal advice",
          "NOT legal advice" in r["note"], f"got {r['note']}")


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
