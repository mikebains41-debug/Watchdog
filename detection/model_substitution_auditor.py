#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
model_substitution_auditor.py -- "Are you getting the model you paid for?"
*** WATCHDOG ***

THE PROBLEM (formalised by Cai, Shi, Zhao, Song -- UC Berkeley, arXiv 2504.04715)
--------------------------------------------------------------------------------
A provider advertises model M_spec and bills for it, but silently serves a
cheaper M_alt: a quantized variant (INT8/FP8/NF4), a smaller model, a
differently fine-tuned version, or another family entirely. The user has
black-box access only. Substitution breaks the service agreement, invalidates
reproducible research and benchmarks, and can silently change safety
behaviour.

WHAT THE PAPER PROVES -- AND WHY THIS MODULE IS TEE-FIRST
---------------------------------------------------------
The authors evaluated the software-only detection methods and found them
fundamentally unreliable:
  - TEXT CLASSIFIERS: binary accuracy 48.7-51.7% (i.e. CHANCE) at separating
    quantized from full-precision output, across BERT/T5/GPT-2/LLM2Vec
    embeddings and four model families (Llama3-70B, Gemma2-9b, Mistral-7b,
    Qwen2-72B), 10k training samples each. They simply do not work for
    quantization substitution.
  - IDENTITY PROMPTING ("who are you?"): defeated; quantization does not
    change self-identification, and a system prompt overrides it anyway.
  - LOG-PROBABILITY COMPARISON: defeated by inherent inference
    nondeterminism in production serving.
And three adversarial scenarios make software detection worse:
  - QUANTIZATION SUBSTITUTION: distributional difference too small to see.
  - RANDOMIZED SUBSTITUTION: serve M_alt with probability p; as p falls the
    mixed distribution approaches M_spec and sampling-based detection dies.
  - BENCHMARK EVASION: the provider detects audit-looking queries (hashing,
    embedding similarity) and routes THOSE to the genuine model while
    ordinary traffic gets the substitute.

Their conclusion, and the design of this module: hardware-level attestation
(TEE) is the only currently viable mechanism for provable model integrity.

WATCHDOG'S POSITION
-------------------
Watchdog already holds the pieces the paper says are required: TEE/CC
attestation (detection/attestation.py, detection/cc_integrity_detector.py),
a hash-chained evidence ledger, and real Intel TDX + H200 validation. This
auditor makes that an explicit product answer to a named, published problem.

  TIER 1 (STRONG)   -- TEE attestation: verify the measurement/quote binds
                       the ACTUAL served model weights to the advertised
                       identity. Provable. This is the answer.
  TIER 2 (WEAK)     -- software probes, included ONLY because most providers
                       offer no TEE today. Every Tier-2 result is labelled
                       with the paper's measured failure rate, and a "clean"
                       Tier-2 result NEVER means "no substitution" -- it
                       means "not detected by a method known to fail".
  ANTI-EVASION      -- Tier-2 probes are randomly generated per audit, never
                       drawn from a fixed benchmark set, because benchmark
                       evasion defeats fixed prompts by construction.

SECURITY REVIEW COMPLIANCE: no bare except; no shell; no subprocess; no
network calls (the caller supplies responses); detection only; gated actions.

NOTE: Logic-tested. Tier-1 requires a real TEE quote to verify; the
verifier is injectable so the real path is exercised where a TEE exists.
"""

import hashlib
import secrets
import statistics
from datetime import datetime, timezone

# The paper's measured accuracies for text classification of quantized vs
# full-precision output. ~50% is chance. Carried so every Tier-2 result can
# state its own known weakness.
PAPER_TEXT_CLASSIFIER_ACC = {
    "Llama3-70B-Instruct-FP8": 50.55, "Llama3-70B-Instruct-INT8": 51.60,
    "Gemma2-9b-it-FP8": 49.95, "Gemma2-9b-it-INT8": 49.00,
    "Mistral-7b-v3-Instruct-FP8": 50.55, "Mistral-7b-v3-Instruct-INT8": 49.70,
    "Qwen2-72B-Instruct-FP8": 50.05, "Qwen2-72B-Instruct-INT8": 50.75,
}
SOFTWARE_METHOD_WEAKNESS = (
    "software-only substitution detection is PROVABLY UNRELIABLE: text classifiers "
    "score 48.7-51.7% (chance) against quantization substitution, identity prompting "
    "is defeated by system prompts, and log-probability methods fail on production "
    "inference nondeterminism (arXiv 2504.04715). A clean result here means "
    "'not detected by a method known to fail', NOT 'no substitution'."
)


# ---------------------------------------------------------------------------
# TIER 1 -- TEE attestation (the strong path)
# ---------------------------------------------------------------------------
class TEEModelAttestationVerifier:
    """
    Verifies that a provider's TEE quote binds the SERVED model to the
    ADVERTISED identity. `quote_verifier` is injectable: in production it is
    the platform's real quote-verification routine (Intel TDX / NVIDIA CC /
    dstack); in tests it is a fake. This module never fabricates a verdict
    when the verifier is absent -- it returns TEE_UNAVAILABLE.
    """

    def __init__(self, quote_verifier=None):
        self._verify = quote_verifier
        self.checks = 0
        self.failures = 0

    @staticmethod
    def model_measurement(weights_digest: str, config_digest: str = "") -> str:
        """The value that must appear in the quote: a digest binding weights
        (and optionally serving config) to an identity."""
        return hashlib.sha256(f"{weights_digest}|{config_digest}".encode()).hexdigest()

    def verify(self, advertised_model: str, expected_measurement: str,
               quote: dict) -> dict:
        self.checks += 1
        ts = datetime.now(timezone.utc).isoformat()
        base = {"tier": 1, "method": "tee_attestation", "advertised_model": advertised_model,
                "timestamp": ts, "agent": "TEEModelAttestationVerifier",
                "cite": "Auditing Model Substitution in LLM APIs (arXiv 2504.04715), section 4.3",
                "strength": "PROVABLE -- hardware-backed cryptographic binding"}

        if self._verify is None:
            base.update(type="TEE_UNAVAILABLE", severity="WARNING",
                        detail=("no TEE quote verifier configured; provider offers no hardware "
                                "attestation. Substitution CANNOT be ruled out by software alone."),
                        recommended_action={"action": "request_tee_attested_endpoint",
                                            "detail": "ask the provider for a TEE-attested endpoint; "
                                                      "absent that, treat model identity as unverified",
                                            "risk": "advisory"})
            return base

        try:
            result = self._verify(quote)
        except Exception as e:   # surfaced, never swallowed
            self.failures += 1
            base.update(type="TEE_VERIFICATION_ERROR", severity="CRITICAL",
                        error=f"{type(e).__name__}: {e}",
                        detail="quote verification raised; failed LOUD, not treated as valid")
            return base

        if not isinstance(result, dict):
            base.update(type="TEE_VERIFICATION_ERROR", severity="CRITICAL",
                        detail="verifier returned a non-dict result")
            return base

        base["quote_valid"] = bool(result.get("valid"))
        base["reported_measurement"] = result.get("measurement")
        base["platform"] = result.get("platform")

        if not result.get("valid"):
            self.failures += 1
            base.update(type="TEE_QUOTE_INVALID", severity="CRITICAL",
                        swarm_signal="MODEL_SUBSTITUTION_SUSPECTED",
                        detail=f"quote failed verification: {result.get('reason', 'unspecified')}",
                        recommended_action={"action": "halt_traffic_to_endpoint_gated",
                                            "risk": "gated"})
            return base

        if result.get("measurement") != expected_measurement:
            self.failures += 1
            base.update(type="MODEL_SUBSTITUTION_CONFIRMED", severity="CRITICAL",
                        swarm_signal="MODEL_SUBSTITUTION_CONFIRMED",
                        expected_measurement=expected_measurement,
                        detail=("the TEE-attested measurement of the SERVED model does not match "
                                "the advertised model -- this is proof, not inference"),
                        recommended_action={"action": "halt_traffic_and_preserve_evidence_gated",
                                            "detail": "stop routing to this endpoint; seal the quote "
                                                      "and measurement into the evidence ledger",
                                            "risk": "gated"})
            return base

        base.update(type="MODEL_IDENTITY_ATTESTED", severity="INFO",
                    detail="served model measurement matches the advertised model, hardware-attested")
        return base

    def get_stats(self):
        return {"component": "TEEModelAttestationVerifier", "checks": self.checks,
                "failures": self.failures, "verifier_configured": self._verify is not None}


# ---------------------------------------------------------------------------
# TIER 2 -- software probes (weak; included with their own failure rate)
# ---------------------------------------------------------------------------
class SoftwareSubstitutionProbe:
    """
    Weak, best-effort software checks for providers with no TEE. Every result
    carries the paper's measured failure rate and refuses to say "no
    substitution" -- only "not detected".

    ANTI-EVASION: probe prompts are generated RANDOMLY per audit (a nonce is
    embedded), never taken from a fixed benchmark, because a provider that
    recognises audit queries routes them to the genuine model.
    """

    def __init__(self, min_samples=30):
        self.min_samples = min_samples
        self.audits = 0

    def generate_probes(self, n: int = 8) -> list:
        """Fresh, unguessable probes. The nonce defeats hash/embedding-based
        benchmark evasion; the tasks are deterministic-ish so responses are
        comparable."""
        probes = []
        for _ in range(n):
            nonce = secrets.token_hex(4)
            probes.append({
                "nonce": nonce,
                "prompt": (f"[ref:{nonce}] Reply with exactly three short lines: "
                           f"(1) the integer 7 times 13, (2) the third letter of the word "
                           f"'substitution', (3) the token {nonce} reversed."),
                "anti_evasion": "randomly generated per audit; not from any benchmark set",
            })
        return probes

    def compare_distributions(self, spec_samples: list, actual_samples: list,
                              model_label: str = None) -> dict:
        """A blunt distributional comparison of response lengths/digests. It
        is deliberately simple: the paper shows sophisticated classifiers do
        no better than chance, so complexity here would be false precision."""
        self.audits += 1
        ts = datetime.now(timezone.utc).isoformat()
        base = {"tier": 2, "method": "software_distribution_probe", "timestamp": ts,
                "agent": "SoftwareSubstitutionProbe",
                "cite": "arXiv 2504.04715 sections 4.1-4.2",
                "strength": "WEAK", "known_weakness": SOFTWARE_METHOD_WEAKNESS}
        if model_label and model_label in PAPER_TEXT_CLASSIFIER_ACC:
            base["paper_measured_accuracy_for_this_pair_pct"] = PAPER_TEXT_CLASSIFIER_ACC[model_label]

        if len(spec_samples) < self.min_samples or len(actual_samples) < self.min_samples:
            base.update(type="SOFTWARE_PROBE_UNDERPOWERED", severity="INFO",
                        detail=(f"need >= {self.min_samples} samples per side; even then the method "
                                "is near chance for quantization substitution"))
            return base

        def stats(xs):
            lens = [len(s) for s in xs]
            return {"n": len(xs), "mean_len": statistics.fmean(lens),
                    "stdev_len": statistics.pstdev(lens) if len(lens) > 1 else 0.0,
                    "distinct_ratio": len({hashlib.sha256(s.encode()).hexdigest() for s in xs}) / len(xs)}

        a, b = stats(spec_samples), stats(actual_samples)
        pooled = ((a["stdev_len"] ** 2 + b["stdev_len"] ** 2) / 2.0) ** 0.5
        mean_gap = abs(a["mean_len"] - b["mean_len"])
        if pooled > 0:
            effect = mean_gap / pooled
            effect_basis = "cohens_d"
        else:
            # Zero variance on both sides. Dividing by pooled=0 would report
            # effect 0.0 -- a SILENT FALSE NEGATIVE for an obvious difference
            # (e.g. every spec response 100 chars, every actual 400). With no
            # spread, ANY mean gap is total separation; fall back to a
            # relative gap so the detector cannot miss it.
            rel = mean_gap / max(a["mean_len"], b["mean_len"], 1.0)
            effect = 10.0 * rel if mean_gap > 0 else 0.0
            effect_basis = "zero_variance_relative_gap"
        base.update(spec_stats=a, actual_stats=b, length_effect_size=round(effect, 3),
                    effect_size_basis=effect_basis)

        # A large effect is worth a WEAK flag; a small one proves nothing.
        if effect >= 0.8:
            base.update(type="SOFTWARE_PROBE_DIVERGENCE", severity="WARNING",
                        swarm_signal="MODEL_SUBSTITUTION_SUSPECTED",
                        detail=("response-length distributions differ substantially; this is a WEAK "
                                "signal and could be sampling or serving-config drift, not substitution"),
                        recommended_action={"action": "request_tee_attestation", "risk": "advisory"})
        else:
            base.update(type="SOFTWARE_PROBE_NO_DETECTION", severity="INFO",
                        detail=("no divergence detected -- which, per the cited paper, is the EXPECTED "
                                "result even when substitution IS occurring. Not evidence of honesty."))
        return base

    def get_stats(self):
        return {"component": "SoftwareSubstitutionProbe", "audits": self.audits,
                "min_samples": self.min_samples}


# ---------------------------------------------------------------------------
# The auditor: runs Tier 1, falls back to Tier 2, never conflates them
# ---------------------------------------------------------------------------
class ModelSubstitutionAuditor:
    def __init__(self, tee_verifier=None, min_samples=30):
        self.tee = TEEModelAttestationVerifier(quote_verifier=tee_verifier)
        self.sw = SoftwareSubstitutionProbe(min_samples=min_samples)

    def audit(self, advertised_model: str, expected_measurement: str = None,
              quote: dict = None, spec_samples: list = None,
              actual_samples: list = None, model_label: str = None) -> dict:
        ts = datetime.now(timezone.utc).isoformat()
        out = {"type": "MODEL_SUBSTITUTION_AUDIT", "advertised_model": advertised_model,
               "timestamp": ts, "agent": "ModelSubstitutionAuditor",
               "positioning": ("Watchdog holds the TEE attestation + evidence-ledger layer the "
                               "cited research identifies as the only viable answer; software "
                               "probes are included only as a labelled fallback"),
               "cite": "Cai, Shi, Zhao & Song, arXiv 2504.04715 (UC Berkeley)"}

        tier1 = self.tee.verify(advertised_model, expected_measurement, quote or {})
        out["tier1_tee"] = tier1

        if tier1["type"] in ("MODEL_SUBSTITUTION_CONFIRMED", "TEE_QUOTE_INVALID",
                             "TEE_VERIFICATION_ERROR"):
            out.update(verdict=tier1["type"], severity="CRITICAL",
                       confidence="PROVABLE" if tier1["type"] == "MODEL_SUBSTITUTION_CONFIRMED" else "HIGH",
                       swarm_signal=tier1.get("swarm_signal", "MODEL_SUBSTITUTION_SUSPECTED"),
                       recommended_action=tier1.get("recommended_action"))
            return out
        if tier1["type"] == "MODEL_IDENTITY_ATTESTED":
            out.update(verdict="MODEL_IDENTITY_ATTESTED", severity="INFO", confidence="PROVABLE")
            return out

        # TEE unavailable -> weak fallback, clearly labelled
        if spec_samples and actual_samples:
            tier2 = self.sw.compare_distributions(spec_samples, actual_samples, model_label)
            out["tier2_software"] = tier2
            out.update(verdict=tier2["type"], severity=tier2["severity"],
                       confidence="LOW -- software methods are near chance for quantization substitution",
                       swarm_signal=tier2.get("swarm_signal"),
                       recommended_action=tier2.get("recommended_action"))
        else:
            out.update(verdict="UNVERIFIED", severity="WARNING", confidence="NONE",
                       detail=("no TEE attestation and no samples supplied -- model identity is "
                               "entirely unverified"),
                       recommended_action=tier1.get("recommended_action"))
        return out

    def get_stats(self):
        return {"component": "ModelSubstitutionAuditor",
                "tee": self.tee.get_stats(), "software": self.sw.get_stats()}


if __name__ == "__main__":
    m = TEEModelAttestationVerifier.model_measurement("weights-abc", "cfg-1")
    good = lambda q: {"valid": True, "measurement": m, "platform": "Intel TDX"}
    swapped = lambda q: {"valid": True, "measurement": "different-model-digest", "platform": "Intel TDX"}

    a = ModelSubstitutionAuditor(tee_verifier=good)
    print("[AUDIT] attested ->", a.audit("llama-3.1-70b", m, {"q": 1})["verdict"])
    b = ModelSubstitutionAuditor(tee_verifier=swapped)
    print("[AUDIT] substituted ->", b.audit("llama-3.1-70b", m, {"q": 1})["verdict"])
    c = ModelSubstitutionAuditor()   # no TEE
    r = c.audit("llama-3.1-70b", m, None,
                spec_samples=["x" * 100] * 40, actual_samples=["x" * 101] * 40,
                model_label="Llama3-70B-Instruct-FP8")
    print("[AUDIT] no TEE ->", r["verdict"], "| confidence:", r["confidence"])
    print("        paper accuracy for this pair:",
          r["tier2_software"].get("paper_measured_accuracy_for_this_pair_pct"), "% (chance)")
