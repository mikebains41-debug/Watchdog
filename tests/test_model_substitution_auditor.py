#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_model_substitution_auditor.py  *** WATCHDOG ***

Tests the model-substitution auditor. The important tests are the HONESTY
ones: a clean software result must never be reported as "no substitution",
every software result must carry the paper's measured failure rate, and
probes must be randomly generated so benchmark evasion cannot defeat them.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from detection.model_substitution_auditor import (
    ModelSubstitutionAuditor, TEEModelAttestationVerifier, SoftwareSubstitutionProbe,
    PAPER_TEXT_CLASSIFIER_ACC, SOFTWARE_METHOD_WEAKNESS,
)

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name}{'' if cond else ' ' + detail}")


M = TEEModelAttestationVerifier.model_measurement("weights-abc", "cfg-1")


# ---- Tier 1: TEE ------------------------------------------------------------
def test_measurement_is_deterministic_and_binds_config():
    a = TEEModelAttestationVerifier.model_measurement("w1", "c1")
    b = TEEModelAttestationVerifier.model_measurement("w1", "c1")
    c = TEEModelAttestationVerifier.model_measurement("w1", "c2")
    check("tee: measurement deterministic", a == b)
    check("tee: measurement binds serving config too", a != c)


def test_attested_match():
    v = TEEModelAttestationVerifier(lambda q: {"valid": True, "measurement": M, "platform": "Intel TDX"})
    r = v.verify("llama-3.1-70b", M, {"q": 1})
    check("tee: matching measurement -> MODEL_IDENTITY_ATTESTED",
          r["type"] == "MODEL_IDENTITY_ATTESTED", f"got {r['type']}")
    check("tee: labelled PROVABLE", "PROVABLE" in r["strength"])


def test_substitution_confirmed_is_proof():
    v = TEEModelAttestationVerifier(lambda q: {"valid": True, "measurement": "other", "platform": "TDX"})
    r = v.verify("llama-3.1-70b", M, {"q": 1})
    check("tee: measurement mismatch -> MODEL_SUBSTITUTION_CONFIRMED (CRITICAL)",
          r["type"] == "MODEL_SUBSTITUTION_CONFIRMED" and r["severity"] == "CRITICAL", f"got {r['type']}")
    check("tee: states this is proof, not inference", "proof, not inference" in r["detail"])
    check("tee: remediation gated", r["recommended_action"]["risk"] == "gated")


def test_invalid_quote():
    v = TEEModelAttestationVerifier(lambda q: {"valid": False, "reason": "bad signature"})
    r = v.verify("m", M, {})
    check("tee: invalid quote -> TEE_QUOTE_INVALID (CRITICAL)",
          r["type"] == "TEE_QUOTE_INVALID" and "bad signature" in r["detail"], f"got {r['type']}")


def test_verifier_exception_fails_loud():
    def boom(q):
        raise RuntimeError("enclave unreachable")
    r = TEEModelAttestationVerifier(boom).verify("m", M, {})
    check("tee: verifier exception -> ERROR, never treated as valid",
          r["type"] == "TEE_VERIFICATION_ERROR" and "RuntimeError" in r["error"], f"got {r['type']}")


def test_no_verifier_is_unavailable_not_clean():
    r = TEEModelAttestationVerifier().verify("m", M, {})
    check("tee: no verifier -> TEE_UNAVAILABLE (never a pass)",
          r["type"] == "TEE_UNAVAILABLE" and r["severity"] == "WARNING", f"got {r['type']}")
    check("tee: says substitution cannot be ruled out by software",
          "CANNOT be ruled out" in r["detail"])


def test_non_dict_verifier_result():
    r = TEEModelAttestationVerifier(lambda q: "yes").verify("m", M, {})
    check("tee: malformed verifier result -> ERROR", r["type"] == "TEE_VERIFICATION_ERROR")


# ---- Tier 2: software (the honesty tests) -----------------------------------
def test_probes_are_random_not_benchmark():
    p = SoftwareSubstitutionProbe()
    a = p.generate_probes(6); b = p.generate_probes(6)
    check("anti-evasion: probes differ between audits (defeats benchmark evasion)",
          {x["nonce"] for x in a}.isdisjoint({x["nonce"] for x in b}))
    check("anti-evasion: each probe embeds its nonce in the prompt",
          all(x["nonce"] in x["prompt"] for x in a))
    check("anti-evasion: probes declare they are not from a benchmark set",
          all("not from any benchmark" in x["anti_evasion"] for x in a))


def test_clean_software_result_is_not_no_substitution():
    p = SoftwareSubstitutionProbe(min_samples=10)
    r = p.compare_distributions(["x" * 100] * 20, ["x" * 100] * 20)
    check("honesty: no divergence -> NO_DETECTION, not 'no substitution'",
          r["type"] == "SOFTWARE_PROBE_NO_DETECTION", f"got {r['type']}")
    check("honesty: explicitly says this is the EXPECTED result even when substitution occurs",
          "EXPECTED result even when substitution IS occurring" in r["detail"])
    check("honesty: explicitly says it is not evidence of honesty",
          "Not evidence of honesty" in r["detail"])


def test_every_software_result_carries_the_failure_rate():
    p = SoftwareSubstitutionProbe(min_samples=10)
    for samples in ([["x" * 100] * 20, ["x" * 100] * 20], [["x" * 100] * 20, ["y" * 300] * 20]):
        r = p.compare_distributions(*samples)
        check(f"honesty: result {r['type']} carries the known-weakness statement",
              "PROVABLY UNRELIABLE" in r["known_weakness"] and r["strength"] == "WEAK")


def test_paper_accuracy_attached_when_pair_known():
    p = SoftwareSubstitutionProbe(min_samples=10)
    r = p.compare_distributions(["x" * 100] * 20, ["x" * 100] * 20,
                                model_label="Llama3-70B-Instruct-INT8")
    check("honesty: attaches the paper's measured accuracy for this exact pair (51.6% = chance)",
          r["paper_measured_accuracy_for_this_pair_pct"] == 51.60, f"got {r.get('paper_measured_accuracy_for_this_pair_pct')}")


def test_paper_accuracies_are_all_near_chance():
    vals = list(PAPER_TEXT_CLASSIFIER_ACC.values())
    check("honesty: every cited classifier accuracy is within 48-52% (chance)",
          all(48.0 <= v <= 52.0 for v in vals), f"got {vals}")


def test_large_divergence_is_only_a_weak_flag():
    p = SoftwareSubstitutionProbe(min_samples=10)
    r = p.compare_distributions(["x" * 100] * 20, ["y" * 400] * 20)
    check("software: large divergence -> WARNING only, never CRITICAL",
          r["type"] == "SOFTWARE_PROBE_DIVERGENCE" and r["severity"] == "WARNING", f"got {r}")
    check("software: says it could be drift, not substitution",
          "could be sampling or serving-config drift" in r["detail"])
    check("software: recommends asking for TEE attestation",
          r["recommended_action"]["action"] == "request_tee_attestation")


def test_underpowered():
    r = SoftwareSubstitutionProbe(min_samples=30).compare_distributions(["a"] * 5, ["b"] * 5)
    check("software: too few samples -> UNDERPOWERED", r["type"] == "SOFTWARE_PROBE_UNDERPOWERED")


# ---- Auditor orchestration --------------------------------------------------
def test_auditor_tee_path_wins():
    a = ModelSubstitutionAuditor(tee_verifier=lambda q: {"valid": True, "measurement": "other"})
    r = a.audit("m", M, {"q": 1}, spec_samples=["x"] * 50, actual_samples=["x"] * 50)
    check("auditor: TEE confirmation short-circuits; software tier not consulted",
          r["verdict"] == "MODEL_SUBSTITUTION_CONFIRMED" and "tier2_software" not in r, f"got {r['verdict']}")
    check("auditor: confidence PROVABLE on TEE confirmation", r["confidence"] == "PROVABLE")


def test_auditor_falls_back_labelled_low_confidence():
    a = ModelSubstitutionAuditor()
    r = a.audit("m", M, None, spec_samples=["x" * 100] * 40, actual_samples=["x" * 100] * 40)
    check("auditor: no TEE -> software fallback used", "tier2_software" in r)
    check("auditor: fallback confidence explicitly LOW with the reason",
          r["confidence"].startswith("LOW") and "near chance" in r["confidence"], f"got {r['confidence']}")


def test_auditor_unverified_when_nothing_available():
    r = ModelSubstitutionAuditor().audit("m", M, None)
    check("auditor: no TEE and no samples -> UNVERIFIED (not 'clean')",
          r["verdict"] == "UNVERIFIED" and r["confidence"] == "NONE", f"got {r['verdict']}")


def test_auditor_attested_path():
    a = ModelSubstitutionAuditor(tee_verifier=lambda q: {"valid": True, "measurement": M})
    r = a.audit("m", M, {"q": 1})
    check("auditor: matching attestation -> MODEL_IDENTITY_ATTESTED, PROVABLE",
          r["verdict"] == "MODEL_IDENTITY_ATTESTED" and r["confidence"] == "PROVABLE")


def test_positioning_statement_present():
    r = ModelSubstitutionAuditor().audit("m", M, None)
    check("auditor: states Watchdog holds the TEE layer the research identifies as the answer",
          "only viable answer" in r["positioning"] and "2504.04715" in r["cite"])


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            try:
                fn()
            except Exception as e:
                check(name, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60 + f"\nPASSED: {len(PASSED)}   FAILED: {len(FAILED)}\n" + "=" * 60)
    sys.exit(1 if FAILED else 0)
