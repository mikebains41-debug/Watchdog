#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
operator_guardrail_and_handoff.py -- Operator-Agent Guardrail + Recovery Handoff
*** WATCHDOG ***

Two lessons from the Sep-2026 Hugging Face research pass, turned into code:

1. DON'T BUILD YOUR OWN AGENT GUARDRAIL. Step-level, pre-execution agent
   guardrails are a crowded, active research area with strong open options:
   LlamaFirewall (Meta, open-source: PromptGuard 2 + AlignmentCheck +
   CodeShield, arXiv 2505.03574), StepGuard (2608.24777), ToolSafe
   (2601.10156), temporal-constraint enforcement (2512.23738). Watchdog's
   planned autonomous OPERATOR agent (the AI that runs Watchdog) needs a
   guardrail on every action it proposes. Same lesson as the ProtectAI
   classifier: use the best open tool for the commodity layer, keep
   Watchdog's own bounded-autonomy policy as the hard floor underneath.
   -> OperatorGuardrailAdapter: wraps LlamaFirewall when installed; degrades
      HONESTLY to Watchdog's own allowlist/denylist + gating rules when not.
      Every proposed operator action passes BOTH: the open guardrail (if
      present) AND Watchdog's non-negotiable floor (destructive actions are
      never auto-approved, regardless of what any guardrail says).

2. WATCHDOG FEEDS RECOVERY SYSTEMS; IT DOES NOT REPLACE THEM. Production
   self-healing for GPU fleets is mature: ByteRobust (ByteDance, 2509.16293),
   Unicron (2401.00134), Concordia GPU-resident checkpointing (2606.23521),
   C4 (2406.04594), "From Detection to Recovery: 504 GPUs" (2605.09370).
   These systems speak checkpoint / migrate / resume / drain / quarantine.
   Watchdog's job is to DETECT and GATE, then hand a clean, attributed
   incident to the recovery system in ITS vocabulary.
   -> RecoveryHandoffAdapter: converts Watchdog incidents into a
      recovery-system handoff record (normalized action vocabulary, affected
      resources, urgency, evidence pointer, gating state). Emits ONLY when
      the incident is gate-approved or auto-safe; never triggers recovery
      on an unapproved destructive action.

SECURITY REVIEW COMPLIANCE: no bare except; no shell; no subprocess; the
hard floor can't be bypassed by any injected guardrail result; destructive
actions require explicit human approval to reach the handoff.

NOTE: Logic-tested with the fallback path and an injected fake guardrail.
Real LlamaFirewall path exercised on a machine with the package installed.
"""

from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Watchdog's non-negotiable floor (independent of any external guardrail)
# ---------------------------------------------------------------------------
AUTO_SAFE_ACTIONS = {
    "log", "raise_alert", "checkpoint_critical_state", "enable_tmr_on_critical_workloads",
    "raise_sdc_seu_monitor_sensitivity", "flag_results_window_suspect",
    "quarantine_model_chmod_000_gated",   # reversible; never deletes
    "collect_forensics", "request_human_review",
}
DESTRUCTIVE_ACTIONS = {
    "delete_data", "wipe_keys", "deorbit", "permanent_shutdown", "kill_process",
    "power_cycle_gpu", "evacuate_workload", "reset_gpu_memory", "revoke_token",
    "pause_sensitive_workloads", "disable_batching_for_model", "block_egress_endpoint",
    "retire_part", "isolate_sandbox",
}
NEVER_ALLOWED = {"delete_data", "wipe_keys", "deorbit", "permanent_shutdown"}


class OperatorGuardrailAdapter:
    """
    `guardrail` is injectable: an object with .scan(action: dict) -> dict
    {"decision": "ALLOW"|"BLOCK", "reason": str}. Leave None to try
    LlamaFirewall. Watchdog's floor is applied regardless.
    """

    def __init__(self, guardrail=None, loader=None):
        self._guard = guardrail
        self._loader = loader
        self.mode = "unloaded"
        self.load_error = None
        self.decisions = 0
        self.blocked = 0

    def load(self) -> dict:
        if self._guard is not None:
            self.mode = "injected_guardrail"
            return {"type": "GUARDRAIL_LOADED", "mode": self.mode}
        try:
            if self._loader is not None:
                self._guard = self._loader()
            else:
                # Real path: LlamaFirewall (pip install llamafirewall). Wrapped so
                # a missing/incompatible install degrades honestly.
                from llamafirewall import LlamaFirewall  # noqa: WPS433 (optional dep)
                self._guard = _LlamaFirewallShim(LlamaFirewall())
            self.mode = "llamafirewall"
            self.load_error = None
        except Exception as e:  # surfaced, never swallowed
            self._guard = None
            self.mode = "watchdog_floor_only"
            self.load_error = f"{type(e).__name__}: {e}"
        return {"type": "GUARDRAIL_LOADED" if self._guard else "GUARDRAIL_FALLBACK",
                "mode": self.mode, "load_error": self.load_error}

    def _floor(self, action: str, human_approved: bool) -> dict:
        if action in NEVER_ALLOWED:
            return {"floor": "BLOCK", "reason": "action is on Watchdog's NEVER_ALLOWED list"}
        if action in DESTRUCTIVE_ACTIONS and not human_approved:
            return {"floor": "GATE", "reason": "destructive action requires explicit human approval"}
        if action in AUTO_SAFE_ACTIONS or (action in DESTRUCTIVE_ACTIONS and human_approved):
            return {"floor": "ALLOW", "reason": "auto-safe or human-approved"}
        return {"floor": "GATE", "reason": "unknown action -> gated by default"}

    def evaluate(self, proposed: dict, human_approved: bool = False) -> dict:
        """proposed: {"action": str, "target": str, "rationale": str, "context": {...}}"""
        self.decisions += 1
        if self.mode == "unloaded":
            self.load()
        action = str(proposed.get("action", "")).lower()
        ts = datetime.now(timezone.utc).isoformat()
        floor = self._floor(action, human_approved)

        ext = {"decision": "N/A", "reason": "no external guardrail loaded"}
        if self._guard is not None:
            try:
                ext = self._guard.scan(proposed)
            except Exception as e:
                ext = {"decision": "ERROR", "reason": f"{type(e).__name__}: {e}"}

        # Combine: the floor can only make things STRICTER, never looser.
        if floor["floor"] == "BLOCK":
            final = "BLOCK"
        elif ext.get("decision") == "BLOCK":
            final = "BLOCK"
        elif floor["floor"] == "GATE":
            final = "GATE"
        elif ext.get("decision") == "ERROR":
            final = "GATE"            # guardrail failure -> fail closed to a gate
        else:
            final = "ALLOW"
        if final == "BLOCK":
            self.blocked += 1

        return {
            "type": "OPERATOR_ACTION_DECISION",
            "action": action,
            "target": proposed.get("target"),
            "decision": final,
            "watchdog_floor": floor,
            "external_guardrail": {"mode": self.mode, **ext},
            "human_approved": human_approved,
            "timestamp": ts,
            "agent": "OperatorGuardrailAdapter",
            "cite": ("LlamaFirewall (2505.03574); StepGuard (2608.24777); ToolSafe (2601.10156); "
                     "temporal constraints for agents (2512.23738)"),
            "rule": "external guardrail can only tighten; Watchdog's floor is never overridden",
        }

    def get_stats(self):
        return {"component": "OperatorGuardrailAdapter", "mode": self.mode,
                "decisions": self.decisions, "blocked": self.blocked, "load_error": self.load_error}


class _LlamaFirewallShim:
    """Adapts LlamaFirewall's API to .scan(action)->{decision, reason}.
    Kept minimal; exact LlamaFirewall message types are set on a real install."""

    def __init__(self, lf):
        self._lf = lf

    def scan(self, proposed: dict) -> dict:
        text = f"{proposed.get('action')} {proposed.get('target')} :: {proposed.get('rationale', '')}"
        result = self._lf.scan(text)   # real API: returns a ScanResult with .decision
        decision = getattr(result, "decision", None)
        name = getattr(decision, "name", str(decision)).upper()
        return {"decision": "BLOCK" if "BLOCK" in name else "ALLOW",
                "reason": getattr(result, "reason", "llamafirewall")}


# ---------------------------------------------------------------------------
# Recovery-system handoff
# ---------------------------------------------------------------------------
# Watchdog recommended_action -> recovery-system vocabulary
ACTION_TO_RECOVERY = {
    "evacuate_workload": "migrate",
    "evacuate_workload_from_latched_part": "migrate",
    "schedule_gpu_out_and_preserve_evidence": "drain",
    "quarantine_divergent_lane_gpu": "quarantine",
    "isolate_sandbox": "quarantine",
    "isolate_sandbox_and_raise_gated": "quarantine",
    "power_cycle_gpu": "reset",
    "power_cycle_latched_part": "reset",
    "checkpoint_critical_state": "checkpoint",
    "gated_rerun_and_flag_batch": "resume_from_checkpoint",
    "reopen_model_validation": "hold_for_validation",
    "retire_part_migrate_workload_gated": "retire",
    "block_egress_endpoint_gated": "network_block",
}
RECOVERY_VOCAB = {"checkpoint", "migrate", "resume_from_checkpoint", "drain", "quarantine",
                  "reset", "retire", "hold_for_validation", "network_block"}


class RecoveryHandoffAdapter:
    def __init__(self):
        self.handoffs = 0
        self.withheld = 0

    def build(self, incident: dict, gate_state: str, evidence_ref: str = None) -> dict:
        """
        incident: a Watchdog incident/alert dict (has type/incident, severity,
                  recommended_action, contributing alerts, gpu/host fields).
        gate_state: 'auto_safe' | 'human_approved' | 'pending' | 'denied'
        Returns a handoff record for a recovery system, or a WITHHELD record
        if the incident is not cleared to act.
        """
        ts = datetime.now(timezone.utc).isoformat()
        rec = incident.get("recommended_action") or {}
        wd_action = str(rec.get("action", "")).lower()
        recovery_action = ACTION_TO_RECOVERY.get(wd_action)
        # strip a trailing _gated suffix if present
        if recovery_action is None and wd_action.endswith("_gated"):
            recovery_action = ACTION_TO_RECOVERY.get(wd_action[:-6])

        base = {
            "type": "RECOVERY_HANDOFF",
            "source": "watchdog",
            "incident": incident.get("incident") or incident.get("type"),
            "severity": incident.get("severity"),
            "watchdog_action": wd_action,
            "recovery_action": recovery_action,
            "affected": {
                "gpu_index": incident.get("gpu_index") or incident.get("gpu_id"),
                "host": incident.get("host"),
                "model_id": incident.get("model_id"),
                "sandbox": incident.get("sandbox"),
            },
            "urgency": "immediate" if incident.get("severity") == "CRITICAL" else "scheduled",
            "evidence_ref": evidence_ref,
            "gate_state": gate_state,
            "timestamp": ts,
            "agent": "RecoveryHandoffAdapter",
            "cite": ("ByteRobust (2509.16293); Unicron (2401.00134); Concordia (2606.23521); "
                     "C4 (2406.04594); From Detection to Recovery, 504 GPUs (2605.09370)"),
            "positioning": "Watchdog detects and gates; the recovery system executes",
        }

        destructive = (wd_action in DESTRUCTIVE_ACTIONS
                       or wd_action.rstrip("_gated") in DESTRUCTIVE_ACTIONS
                       or recovery_action in {"migrate", "drain", "quarantine", "reset", "retire",
                                              "network_block"})
        if destructive and gate_state not in ("human_approved", "auto_safe"):
            self.withheld += 1
            base["type"] = "RECOVERY_HANDOFF_WITHHELD"
            base["reason"] = f"destructive recovery action requires approval; gate_state={gate_state}"
            return base
        if recovery_action is None:
            self.withheld += 1
            base["type"] = "RECOVERY_HANDOFF_UNMAPPED"
            base["reason"] = "no recovery vocabulary for this Watchdog action; human routes it"
            return base

        self.handoffs += 1
        base["ready_to_execute"] = True
        return base

    def get_stats(self):
        return {"component": "RecoveryHandoffAdapter", "handoffs": self.handoffs,
                "withheld": self.withheld}


if __name__ == "__main__":
    g = OperatorGuardrailAdapter()
    print("[GUARD]", g.load()["type"], g.mode)
    print("  checkpoint:", g.evaluate({"action": "checkpoint_critical_state", "target": "gpu0"})["decision"])
    print("  evacuate (no approval):", g.evaluate({"action": "evacuate_workload", "target": "gpu0"})["decision"])
    print("  evacuate (approved):", g.evaluate({"action": "evacuate_workload", "target": "gpu0"}, human_approved=True)["decision"])
    print("  wipe_keys (approved!):", g.evaluate({"action": "wipe_keys", "target": "vault"}, human_approved=True)["decision"])

    h = RecoveryHandoffAdapter()
    inc = {"incident": "DEGRADING_SILICON_INCIDENT", "severity": "CRITICAL", "gpu_index": 2,
           "recommended_action": {"action": "schedule_gpu_out_and_preserve_evidence", "risk": "gated"}}
    print("[HANDOFF pending]", h.build(inc, "pending")["type"])
    print("[HANDOFF approved]", h.build(inc, "human_approved")["type"], "->", h.build(inc, "human_approved")["recovery_action"])
