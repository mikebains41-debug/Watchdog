#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
aibom_jurisdiction_profiles.py -- Multi-Jurisdiction AIBOM Compliance Profiles
Part of Watchdog AI-Attack Detection Suite.

WHY
---
The CycloneDX ML-BOM format is universal, but the REQUIRED FIELDS differ by
jurisdiction. A model that satisfies the EU AI Act can still fail China's
GB 45438-2025 (which demands a provider code + filing number that the EU
doesn't) or the US CISA "SBOM for AI" minimum elements. A company selling
into EU + US + China + Singapore + Canada needs to know, per component,
WHICH regimes it satisfies and exactly what's missing for each.

This layer takes AIBOM component metadata (the same manifest fields
aibom_generator already reads, plus jurisdiction-specific ones) and checks
it against each regime's required field set, producing a per-jurisdiction
gap report. One inventory, checked against every market.

JURISDICTIONS & SOURCES (as of Aug 2026)
----------------------------------------
- EU        : EU AI Act Art. 11 (Annex IV tech docs) + Art. 53(1d) GPAI
              training-data summary (effective 2 Aug 2025); Art. 50 marking.
- US_NIST   : NIST AI RMF -- model/system card fields (intended use,
              performance, limitations, bias eval). Voluntary federal baseline.
- US_CISA   : CISA "SBOM for AI: Minimum Elements" -- component inventory +
              provenance + cryptographic hashes + timestamps.
- US_OMB    : OMB Dec-2025 federal LLM procurement memo -- acceptable-use
              policy, model/system card, (enhanced) system prompts, safety
              filters, bias evaluations.
- CHINA     : GB 45438-2025 (mandatory, eff. 1 Sep 2025) -- provider code,
              content ID, generation timestamp; CAC algorithm-filing/Beian
              registration number; explicit+implicit content labels.
              NOTE: China's schema does NOT map onto EU Art. 50 or C2PA.
- SINGAPORE : Model AI Governance Framework (+ Agentic AI addendum Jan 2026)
              -- model provenance, training-data description, known limitations.
- ISO_42001 : AI management system standard -- inventory, supplier governance,
              change control (version + provenance + owner).
- CANADA    : No binding federal AI law (AIDA died Jan 2025). Operative:
              ISED Voluntary Code of Conduct (data-provenance documentation,
              capability/risk/mitigation summaries, incident disclosure);
              PIPEDA / Quebec Law 25 automated-decision transparency; OSFI
              E-23 model-risk for financial institutions.

All checks are pure field-presence logic over metadata. No network, no
model load, fully testable. This reports compliance GAPS; it does not
give legal advice (stated in every result).

REMEDIATION
-----------
Reporting only. Closing a gap is a documentation/process action (record
the missing field, complete the filing), never a runtime action.
"""

from datetime import datetime, timezone


# Each jurisdiction: the metadata fields a component MUST have to satisfy it.
# Field names are the keys expected in the component's manifest metadata.
JURISDICTION_REQUIRED_FIELDS = {
    "EU": {
        "fields": ["license", "training_data", "intended_purpose",
                   "provider", "risk_classification"],
        "citation": "EU AI Act Art. 11 (Annex IV) + Art. 53(1d) GPAI",
        "binding": True,
    },
    "US_NIST": {
        "fields": ["intended_purpose", "performance_metrics", "limitations",
                   "bias_evaluation"],
        "citation": "NIST AI RMF model/system card fields",
        "binding": False,
    },
    "US_CISA": {
        "fields": ["provider", "source", "version", "sha256", "timestamp"],
        "citation": "CISA 'SBOM for AI: Minimum Elements'",
        "binding": False,
    },
    "US_OMB": {
        "fields": ["acceptable_use_policy", "model_card", "safety_filters",
                   "bias_evaluation"],
        "citation": "OMB Dec-2025 federal LLM procurement memo",
        "binding": True,  # binding for federal procurement specifically
        "scope": "US federal procurement only",
    },
    "CHINA": {
        "fields": ["provider_code", "content_id", "generation_timestamp",
                   "cac_filing_number", "content_labels"],
        "citation": "GB 45438-2025 + CAC Interim Measures (mandatory)",
        "binding": True,
        "note": "schema does NOT satisfy EU Art. 50 or C2PA; separate compliance",
    },
    "SINGAPORE": {
        "fields": ["provider", "training_data", "limitations"],
        "citation": "Singapore Model AI Governance Framework (+ Agentic 2026)",
        "binding": False,
    },
    "ISO_42001": {
        "fields": ["version", "source", "owner", "change_control"],
        "citation": "ISO/IEC 42001 AI management system",
        "binding": False,
    },
    "CANADA": {
        "fields": ["training_data", "capability_summary", "risk_summary",
                   "mitigation_summary"],
        "citation": "ISED Voluntary Code of Conduct; PIPEDA/Quebec Law 25",
        "binding": False,
        "note": "AIDA died Jan 2025; voluntary code is operative baseline",
    },
}

ALL_JURISDICTIONS = list(JURISDICTION_REQUIRED_FIELDS.keys())


def _component_fields(component_meta: dict, sha256: str = None,
                      version: str = None) -> dict:
    """Normalize what we know about a component into a flat field dict.
    sha256/version can come from the AIBOM inventory even if not in the
    manifest, so they're injectable."""
    fields = dict(component_meta or {})
    if sha256 and not fields.get("sha256"):
        fields["sha256"] = sha256
    if version and not fields.get("version"):
        fields["version"] = version
    # timestamp is provided by the AIBOM at generation time
    fields.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    return fields


def check_component(component_name: str,
                    component_meta: dict,
                    jurisdictions: list = None,
                    sha256: str = None,
                    version: str = None) -> dict:
    """
    Check one component's metadata against each requested jurisdiction.
    Returns per-jurisdiction satisfied/missing.
    """
    jurisdictions = jurisdictions or ALL_JURISDICTIONS
    fields = _component_fields(component_meta, sha256=sha256, version=version)

    results = {}
    for j in jurisdictions:
        spec = JURISDICTION_REQUIRED_FIELDS.get(j)
        if not spec:
            results[j] = {"status": "UNKNOWN_JURISDICTION"}
            continue
        missing = [f for f in spec["fields"]
                   if not fields.get(f) or str(fields.get(f)).strip() in ("", "UNPINNED", "UNKNOWN")]
        satisfied = (len(missing) == 0)
        results[j] = {
            "status": "SATISFIED" if satisfied else "GAPS",
            "missing_fields": missing,
            "citation": spec["citation"],
            "binding": spec["binding"],
        }
        if "scope" in spec:
            results[j]["scope"] = spec["scope"]
        if "note" in spec:
            results[j]["note"] = spec["note"]

    satisfied_regions = [j for j, r in results.items() if r.get("status") == "SATISFIED"]
    return {
        "component": component_name,
        "satisfied_jurisdictions": satisfied_regions,
        "per_jurisdiction": results,
    }


def check_aibom(aibom_result: dict,
                manifest: dict = None,
                jurisdictions: list = None) -> dict:
    """
    Take the result of build_aibom (which has an 'aibom' with components) plus
    the manifest metadata, and produce a fleet-wide multi-jurisdiction report.
    """
    jurisdictions = jurisdictions or ALL_JURISDICTIONS
    manifest = manifest or {}
    components = aibom_result.get("aibom", {}).get("components", [])

    per_component = []
    # roll-up: how many components fully satisfy each jurisdiction
    jur_satisfied_count = {j: 0 for j in jurisdictions}

    for comp in components:
        name = comp.get("name", "")
        version = comp.get("version")
        sha256 = None
        for h in comp.get("hashes", []):
            if h.get("alg") == "SHA-256":
                sha256 = h.get("content")
        meta = manifest.get(name) or {}
        res = check_component(name, meta, jurisdictions=jurisdictions,
                              sha256=sha256, version=version)
        per_component.append(res)
        for j in res["satisfied_jurisdictions"]:
            jur_satisfied_count[j] += 1

    total = len(components)
    summary = {}
    for j in jurisdictions:
        spec = JURISDICTION_REQUIRED_FIELDS[j]
        summary[j] = {
            "components_satisfied": jur_satisfied_count[j],
            "components_total": total,
            "fully_compliant": (jur_satisfied_count[j] == total and total > 0),
            "binding": spec["binding"],
            "citation": spec["citation"],
        }

    fully_compliant_regions = [j for j, s in summary.items() if s["fully_compliant"]]
    status = "MULTI_JURISDICTION_COMPLIANT" if len(fully_compliant_regions) == len(jurisdictions) \
        else "JURISDICTION_GAPS_FOUND"

    return {
        "status": status,
        "component_count": total,
        "fully_compliant_jurisdictions": fully_compliant_regions,
        "summary_by_jurisdiction": summary,
        "per_component": per_component,
        "note": ("Field-presence compliance mapping across jurisdictions. "
                 "NOT legal advice. China GB 45438 does not satisfy EU Art. 50 "
                 "or C2PA -- treat as separate. Simulation-based; keep field "
                 "sets current as regulations evolve."),
    }


if __name__ == "__main__":
    # Demo: one component with partial metadata.
    demo_meta = {
        "provider": "GPU Optimizer Inc.",
        "source": "https://huggingface.co/x",
        "version": "1.0",
        "license": "Apache-2.0",
        "training_data": "documented-corpus-v1",
        "intended_purpose": "GPU anomaly detection",
        "risk_classification": "limited",
        # deliberately missing China's provider_code / cac_filing_number
    }
    r = check_component("watchdog-model.safetensors", demo_meta)
    print("[JURISDICTION] satisfied:", r["satisfied_jurisdictions"])
    for j, res in r["per_jurisdiction"].items():
        if res["status"] == "GAPS":
            print(f"  {j}: missing {res['missing_fields']}")
