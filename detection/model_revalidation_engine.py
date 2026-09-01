#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
model_revalidation_engine.py -- Continuous Model Integrity (Part 2)
Revalidation-Trigger Engine + Regulator Evidence-Package Generator
Part of Watchdog AI-Attack Detection Suite.

3. RevalidationTriggerEngine
   OSFI E-23 and SR 26-2 both state: a model modification, a performance
   breach, or a significant data change must REOPEN validation
   automatically -- "not waiting for the annual review." This engine watches
   the signals Watchdog already produces (drift, SDC/integrity, AIBOM/
   provenance change, sandbox/tamper) and fires a REVALIDATION_REQUIRED
   event for the affected model, scaled by its risk tier (a HIGH-tier model
   triggers on less than a LOW-tier one -- E-23's proportionality).

   IMPORTANT (gated, never auto-block): this engine ALERTS and RECOMMENDS
   revalidation. It does NOT auto-block or auto-disable a live production
   model. Auto-blocking a live insurance/pharma model on a threshold could
   itself be a serious incident; the decision stays with a human, matching
   Watchdog's remediation discipline throughout.

4. EvidencePackageGenerator
   FDA/EMA want an "inspection-ready" validation package; E-23/SR 26-2 want
   an attestation roll-up (tiering, validation coverage, monitoring status,
   open findings). Watchdog already produces the RAW evidence (ledger,
   AIBOM, drift results, incidents). This assembles it into the regulator-
   facing structure with a tamper-evident hash chain, so the package itself
   is auditable.

Pure stdlib. Fully testable.

NOTE: Logic-tested. Produces compliance EVIDENCE; does not by itself
constitute regulatory compliance. Not legal advice.
"""

import hashlib
import json
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# 3 -- Revalidation trigger engine
# ---------------------------------------------------------------------------
# Signals that reopen validation, per E-23 / SR 26-2. Each carries a base
# weight; tier multipliers make HIGH-risk models more sensitive.
TRIGGER_SIGNALS = {
    "MODEL_REVALIDATION_REQUIRED": {"weight": 1.0, "reason": "performance breach / drift (E-23, SR 26-2)"},
    "MODEL_DRIFT_DETECTED": {"weight": 0.5, "reason": "moderate drift (monitor)"},
    "SDC_CORRUPTION_DETECTED": {"weight": 1.0, "reason": "compute integrity breach"},
    "WEIGHT_DRIFT_DETECTED": {"weight": 1.0, "reason": "model modification (weights changed)"},
    "WEIGHT_SWAP_DETECTED": {"weight": 1.0, "reason": "model modification (file swapped)"},
    "MODEL_TAMPER_CONFIRMED": {"weight": 1.0, "reason": "model tamper"},
    "MODEL_TAMPER_HARDWARE_MISMATCH": {"weight": 1.0, "reason": "model/hardware footprint mismatch"},
    "PROVENANCE_GAPS_FOUND": {"weight": 0.6, "reason": "significant data/provenance change (AIBOM)"},
    "AGENT_SANDBOX_ESCAPE": {"weight": 0.8, "reason": "environment integrity breach"},
    "DEGRADING_SILICON_INCIDENT": {"weight": 0.8, "reason": "hardware degradation affecting model"},
}

TIER_THRESHOLD = {"HIGH": 0.5, "MEDIUM": 0.8, "LOW": 1.0}  # lower = more sensitive


class RevalidationTriggerEngine:
    def __init__(self, register=None):
        # register: a ModelRiskRegister (optional) to look up tiers
        self.register = register
        self._pending = {}   # model_id -> accumulated trigger score + reasons
        self.triggers_fired = 0

    def _tier_for(self, model_id: str) -> str:
        if self.register is not None:
            e = self.register.get(model_id)
            if e:
                return e.get("risk_tier", "MEDIUM")
        return "MEDIUM"

    def observe(self, model_id: str, alert: dict) -> dict:
        """Feed a Watchdog alert attributed to a model. Returns a trigger
        decision (fires when the tier-scaled threshold is reached)."""
        atype = alert.get("swarm_signal") or alert.get("type")
        spec = TRIGGER_SIGNALS.get(atype)
        if spec is None:
            return {"type": "NO_TRIGGER", "model_id": model_id, "signal": atype}

        st = self._pending.setdefault(model_id, {"score": 0.0, "reasons": []})
        st["score"] += spec["weight"]
        st["reasons"].append({"signal": atype, "reason": spec["reason"]})

        tier = self._tier_for(model_id)
        threshold = TIER_THRESHOLD.get(tier, 0.8)

        if st["score"] >= threshold:
            self.triggers_fired += 1
            reasons = list(st["reasons"])
            self._pending[model_id] = {"score": 0.0, "reasons": []}  # reset after firing
            return {
                "type": "REVALIDATION_TRIGGERED",
                "severity": "CRITICAL" if tier == "HIGH" else "WARNING",
                "model_id": model_id,
                "risk_tier": tier,
                "trigger_score": round(st["score"] if st["score"] else sum(
                    TRIGGER_SIGNALS[r["signal"]]["weight"] for r in reasons), 2),
                "threshold": threshold,
                "reasons": reasons,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent": "RevalidationTriggerEngine",
                "recommended_action": {
                    "action": "reopen_model_validation",
                    "detail": ("open a validation review for this model; independent "
                               "review per E-23 (separate from development)"),
                    "risk": "gated_no_autoblock",
                },
                "gating_note": ("ALERT + RECOMMEND only. Does NOT auto-block or "
                                "disable the live model; that decision is human."),
                "regulatory_clause": [
                    "OSFI E-23: model modification / performance breach / data change prompts a review",
                    "SR 26-2: revalidation triggers on breach or material change",
                    "FDA/EMA: change-control + revalidation for AI affecting GxP data",
                ],
            }
        return {"type": "TRIGGER_ACCUMULATING", "model_id": model_id,
                "score": round(st["score"], 2), "threshold": threshold, "risk_tier": tier}

    def get_stats(self):
        return {"component": "RevalidationTriggerEngine",
                "triggers_fired": self.triggers_fired,
                "models_pending": len(self._pending)}


# ---------------------------------------------------------------------------
# 4 -- Regulator evidence-package generator
# ---------------------------------------------------------------------------
class EvidencePackageGenerator:
    """
    Assembles Watchdog's raw evidence into a regulator-facing package with a
    tamper-evident hash chain. Two framings from the same data:
      - FDA/EMA "inspection-ready validation package" (pharma)
      - E-23 / SR 26-2 "attestation roll-up" (insurance/finance)
    """

    def __init__(self):
        self._chain_prev = "0" * 64

    def _hash(self, obj) -> str:
        return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()

    def _chain(self, section_name: str, content) -> dict:
        h = self._hash({"prev": self._chain_prev, "section": section_name, "content": content})
        entry = {"section": section_name, "content": content,
                 "prev_hash": self._chain_prev, "hash": h}
        self._chain_prev = h
        return entry

    def build(self, model_entry: dict, drift_results: list, integrity_events: list,
              aibom_component: dict = None, revalidation_events: list = None,
              human_reviews: list = None, framing: str = "fda") -> dict:
        """
        model_entry: from ModelRiskRegister.get(model_id)
        drift_results: list of ModelDriftMonitor.check() results
        integrity_events: SDC/tamper/sandbox alerts attributed to the model
        aibom_component: the model's AIBOM entry (provenance/hash/license)
        revalidation_events: RevalidationTriggerEngine outputs
        human_reviews: [{reviewer, date, decision, notes}] -- FDA wants these
        framing: 'fda' (pharma) or 'e23' (insurance/finance)
        """
        self._chain_prev = "0" * 64
        model_id = model_entry.get("model_id", "unknown")
        meta = model_entry.get("metadata", {})

        sections = []
        # 1. identity + provenance (FDA: data/model provenance; E-23: inventory)
        sections.append(self._chain("model_identity_and_provenance", {
            "model_id": model_id,
            "owner": meta.get("owner"), "purpose": meta.get("purpose"),
            "inputs": meta.get("inputs"), "methodology": meta.get("methodology"),
            "limitations": meta.get("limitations"),
            "risk_tier": model_entry.get("risk_tier"),
            "risk_scores": model_entry.get("risk_scores"),
            "third_party": model_entry.get("third_party"),
            "aibom": aibom_component,
        }))
        # 2. performance + monitoring (FDA: performance benchmarks; E-23: monitoring status)
        latest_drift = drift_results[-1] if drift_results else None
        sections.append(self._chain("performance_and_monitoring", {
            "monitoring_checks": len(drift_results),
            "latest_status": latest_drift.get("type") if latest_drift else "NO_MONITORING_DATA",
            "latest_psi": latest_drift.get("psi") if latest_drift else None,
            "metric_baseline": latest_drift.get("metric_baseline") if latest_drift else None,
            "metric_current": latest_drift.get("metric_current") if latest_drift else None,
            "drift_history": [{"t": d.get("timestamp"), "status": d.get("type"),
                               "psi": d.get("psi")} for d in drift_results],
        }))
        # 3. integrity + change control (FDA: change-control records; E-23: modifications)
        sections.append(self._chain("integrity_and_change_control", {
            "integrity_events": [{"t": e.get("timestamp"), "type": e.get("type"),
                                  "severity": e.get("severity")} for e in integrity_events],
            "revalidation_events": [{"t": r.get("timestamp"), "type": r.get("type"),
                                     "reasons": r.get("reasons")} for r in (revalidation_events or [])],
        }))
        # 4. human review (FDA explicitly wants human-review annotations)
        sections.append(self._chain("human_review_annotations", {
            "reviews": human_reviews or [],
            "independent_review_note": ("E-23: review must be independent from "
                                        "development"),
        }))

        open_findings = [e for e in integrity_events if e.get("severity") in ("CRITICAL", "WARNING")]
        attestation = {
            "risk_tier": model_entry.get("risk_tier"),
            "validation_coverage": "monitored" if drift_results else "unmonitored",
            "monitoring_status": latest_drift.get("type") if latest_drift else "NONE",
            "open_findings": len(open_findings),
            "revalidations_triggered": len(revalidation_events or []),
            "inventory_gaps": model_entry.get("inventory_gaps", []),
        }

        return {
            "type": "REGULATOR_EVIDENCE_PACKAGE",
            "framing": framing,
            "model_id": model_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sections": sections,
            "attestation_rollup": attestation,
            "package_hash": self._chain_prev,
            "tamper_evidence": "sections are SHA-256 hash-chained; any edit breaks the chain",
            "regulatory_mapping": ({
                "fda": ["21 CFR Part 11 §11.10(a) validation, §11.10(e) audit trail",
                        "FDA AI in Drug Development (Jan 2025 draft): provenance, benchmarks, limitations, monitoring",
                        "FDA/EMA Good AI Practice (Jan 2026)", "EU Annex 11"],
                "e23": ["OSFI E-23: inventory, tiering, validation coverage, monitoring, open findings",
                        "SR 26-2: attestation roll-up for examiners", "OSFI B-10 third-party models"],
            }.get(framing, [])),
            "note": ("Assembled from Watchdog evidence. Produces compliance EVIDENCE; "
                     "does not by itself constitute compliance. Not legal advice."),
        }

    @staticmethod
    def verify_chain(package: dict) -> bool:
        """Recompute the hash chain to confirm the package was not edited."""
        prev = "0" * 64
        for s in package.get("sections", []):
            expected = hashlib.sha256(json.dumps(
                {"prev": prev, "section": s["section"], "content": s["content"]},
                sort_keys=True, default=str).encode()).hexdigest()
            if s.get("hash") != expected or s.get("prev_hash") != prev:
                return False
            prev = expected
        return package.get("package_hash") == prev


if __name__ == "__main__":
    eng = RevalidationTriggerEngine()
    print("[TRIGGER]", eng.observe("claims-v1", {"type": "SDC_CORRUPTION_DETECTED"})["type"])
    gen = EvidencePackageGenerator()
    pkg = gen.build({"model_id": "claims-v1", "metadata": {"owner": "risk"}, "risk_tier": "HIGH"},
                    drift_results=[], integrity_events=[], framing="e23")
    print("[EVIDENCE]", pkg["type"], "chain valid:", EvidencePackageGenerator.verify_chain(pkg))
