#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog Swarm Intelligence — Remediation Coordinator (Swarm #2)

Detection/prediction tells you WHAT is happening. This layer decides WHAT
TO DO, coordinated across agents, respecting the gated/auto discipline
already established in the repo's remediation engine.

It does NOT invent new destructive powers. It sequences and gates the
response actions that already exist (or are documented) in
remediation/response.py and remediation/action_switch.py, adding four
pieces of coordination the individual detectors don't have:

1. ESCALATION LADDER -- soft actions before hard ones. A single alert
   never jumps straight to node-evacuate; it climbs log -> block-load ->
   quarantine -> evacuate only as severity/confirmation rises.

2. CONFLICT AVOIDANCE -- two alerts wanting to touch the same GPU in the
   same tick are serialized, and a hard action (evacuate) supersedes a
   pending soft action on the same target so they don't fight.

3. GATING -- auto-safe actions (log, quarantine-file, force-deterministic,
   block-load, egress-block) may fire automatically. Risky/irreversible
   actions (node evacuate, memory reset, token revoke, kill) are GATED and
   emitted as human-approval requests, never executed here.

4. FORENSICS-FIRST -- on an active-attack signal (ECC-break precursor,
   correlated incident), the plan preserves state before any reset:
   evacuate-and-hold, never auto-reset, so evidence survives.

This module produces a REMEDIATION PLAN (an ordered list of action
requests). It does not execute anything itself -- execution stays in the
existing remediation engine, which is what actually holds the gated
approval + Watchdog Switch promotion registry.

NOTE: Simulation-based. Requires real hardware validation. The action
mapping is a coordination policy over documented actions, not proof those
actions execute correctly on live infrastructure.
"""
import collections
from datetime import datetime, timezone


# Action risk classes. Auto-safe = may fire automatically. Gated =
# emitted as a human-approval request only.
AUTO_SAFE = "auto_safe"
GATED = "gated"

# The escalation ladder, softest first. An action is only proposed if the
# situation's severity has climbed to at least its rung.
LADDER = [
    "log",                     # rung 0 -- always safe
    "block_load",              # rung 1 -- stop loading a suspect artifact
    "quarantine_file",         # rung 2 -- chmod 000 + move, reversible
    "force_deterministic",     # rung 2 -- FPNA mitigation, reversible
    "rate_limit_client",       # rung 2 -- gated, throttle a client
    "correlate_and_raise",     # rung 2 -- raise a PID for human review
    "gpu_memory_reset",        # rung 3 -- GATED, disruptive
    "evacuate_workload",       # rung 4 -- GATED, hard, forensics-first
    "revoke_token",            # rung 4 -- GATED, can lock out a service
]

# Map an alert/incident type to its candidate action + risk class + whether
# it is an active-attack signal (forensics-first).
ALERT_ACTION_MAP = {
    # --- security prediction agents ---
    "GPUTHOR_PRECURSOR_PREDICTED": {
        "action": "evacuate_workload", "risk": GATED, "active_attack": True,
        "detail": "evacuate off at-risk GPU before flip; preserve state for forensics",
    },
    "COVERT_COMPUTE_ONSET_PREDICTED": {
        "action": "correlate_and_raise", "risk": AUTO_SAFE, "active_attack": False,
        "detail": "correlate ramping PID vs whitelist, raise for review (no auto-kill)",
    },
    "MODEL_EXTRACTION_PRECURSOR_PREDICTED": {
        "action": "rate_limit_client", "risk": GATED, "active_attack": False,
        "detail": "gated per-client rate limit; do not auto-block legit batch inference",
    },
    # --- model-file / detector-driven (batch 1 & 2) ---
    "MALICIOUS_PICKLE_DETECTED": {
        "action": "quarantine_file", "risk": AUTO_SAFE, "active_attack": False,
        "detail": "quarantine (chmod 000 + move), never delete",
    },
    "DANGEROUS_TEMPLATE_DETECTED": {
        "action": "quarantine_file", "risk": AUTO_SAFE, "active_attack": False,
        "detail": "quarantine GGUF/config with code-exec template",
    },
    "MALFORMED_HEADER": {
        "action": "block_load", "risk": GATED, "active_attack": False,
        "detail": "block load, refetch from trusted source (no delete)",
    },
    "WEIGHT_SWAP_DETECTED": {
        "action": "block_load", "risk": GATED, "active_attack": False,
        "detail": "block load pending change-record confirmation",
    },
    "WEIGHT_DRIFT_DETECTED": {
        "action": "block_load", "risk": GATED, "active_attack": True,
        "detail": "resident weight drift; block inference, reload from sealed source",
    },
    "ECC_BREAK_SUSPECTED": {
        "action": "evacuate_workload", "risk": GATED, "active_attack": True,
        "detail": "evacuate + escalate; do NOT auto-reset (forensics)",
    },
    "FPNA_ATTACK_SUSPECTED": {
        "action": "force_deterministic", "risk": AUTO_SAFE, "active_attack": False,
        "detail": "force deterministic algorithms (reversible)",
    },
    "MICRO_BURST_PATTERN": {
        "action": "correlate_and_raise", "risk": AUTO_SAFE, "active_attack": False,
        "detail": "correlate bursting PID vs whitelist; no auto-kill",
    },
    "LEFTOVER_LOCALS_RESIDUAL": {
        "action": "gpu_memory_reset", "risk": GATED, "active_attack": False,
        "detail": "trigger existing gated memory reset / tenant cleaner",
    },
    # --- correlated incidents (always active-attack, escalated) ---
    "CORRELATED_INCIDENT": {
        "action": "evacuate_workload", "risk": GATED, "active_attack": True,
        "detail": "correlated multi-signal incident; evacuate + preserve forensics",
    },
}

# Severity -> the highest-rung ACTION NAME permitted. Prevents a
# low-severity alert from proposing a hard/disruptive action even if its
# map entry names one. WARNING permits soft review/mitigation actions (up
# to correlate_and_raise) but NOT the disruptive tier (gpu_memory_reset /
# evacuate / revoke), which require CRITICAL. INFO is log-only.
SEVERITY_CEILING_ACTION = {
    "INFO": "log",
    "WARNING": "correlate_and_raise",
    "CRITICAL": "revoke_token",   # top of ladder
}


def _rung(action: str) -> int:
    return LADDER.index(action) if action in LADDER else 0


class RemediationCoordinator:
    """
    Consumes alerts/incidents, produces an ordered, de-conflicted,
    gating-aware remediation plan. Executes nothing -- the plan is handed
    to the existing remediation engine.
    """

    def __init__(self):
        self.plan_count = 0
        self.auto_dispatched = 0
        self.gated_requests = 0

    def build_plan(self, alerts: list) -> dict:
        """
        alerts: list of alert/incident dicts (as produced by the swarm's
        ingest()). Returns a plan dict with ordered actions.
        """
        # Map each alert to a candidate action, honoring severity ceiling.
        candidates = []
        for alert in alerts:
            atype = alert.get("type")
            entry = ALERT_ACTION_MAP.get(atype)
            if not entry:
                # unknown alert -> log only, never guess a destructive action
                entry = {"action": "log", "risk": AUTO_SAFE,
                         "active_attack": False, "detail": "no action mapping; log"}
            severity = alert.get("severity", "WARNING")
            ceiling_action = SEVERITY_CEILING_ACTION.get(severity, "correlate_and_raise")
            max_rung = _rung(ceiling_action)
            action = entry["action"]
            # Severity gate: if the mapped action is above what this severity
            # permits, step it DOWN TO log (the universal safe floor) rather
            # than indexing blindly into the ladder -- stepping to whatever
            # action happens to sit at max_rung could swap in an unrelated
            # action (e.g. turn "correlate_and_raise" into "force_deterministic").
            if _rung(action) > max_rung:
                action = "log"
            candidates.append({
                "target_gpu": alert.get("gpu", alert.get("gpu_id", 0)),
                "source_alert": atype,
                "action": action,
                "risk": entry["risk"],
                "active_attack": entry["active_attack"],
                "detail": entry["detail"],
                "severity": severity,
            })

        # Conflict avoidance: per target GPU, keep only the HIGHEST-rung
        # action (a hard action supersedes pending soft ones on the same
        # target so they don't fight). Preserve all distinct targets.
        by_target = collections.defaultdict(list)
        for c in candidates:
            by_target[c["target_gpu"]].append(c)

        resolved = []
        for target, group in by_target.items():
            # highest rung wins for this target
            winner = max(group, key=lambda c: _rung(c["action"]))
            # if ANY alert on this target is an active attack, force
            # forensics-first framing even if the winner wasn't the attack one
            active = any(c["active_attack"] for c in group)
            winner = dict(winner)
            winner["forensics_first"] = active and _rung(winner["action"]) >= _rung("gpu_memory_reset")
            winner["superseded"] = [c["action"] for c in group if c is not winner]
            resolved.append(winner)

        # Order the plan softest-first (execute reversible/auto actions
        # before proposing disruptive gated ones).
        resolved.sort(key=lambda c: _rung(c["action"]))

        # Split into auto-dispatch vs gated-approval.
        plan_actions = []
        for r in resolved:
            is_gated = (r["risk"] == GATED)
            # forensics-first NEVER auto-resets: force gating on those.
            if r.get("forensics_first"):
                is_gated = True
            action_record = {
                "target_gpu": r["target_gpu"],
                "action": r["action"],
                "mode": "gated_approval_request" if is_gated else "auto_dispatch",
                "source_alert": r["source_alert"],
                "severity": r["severity"],
                "detail": r["detail"],
                "forensics_first": r.get("forensics_first", False),
                "superseded_actions": r["superseded"],
            }
            if is_gated:
                self.gated_requests += 1
            else:
                self.auto_dispatched += 1
            plan_actions.append(action_record)

        self.plan_count += 1
        return {
            "type": "REMEDIATION_PLAN",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_count": len(plan_actions),
            "auto_dispatch_count": sum(1 for a in plan_actions if a["mode"] == "auto_dispatch"),
            "gated_request_count": sum(1 for a in plan_actions if a["mode"] == "gated_approval_request"),
            "actions": plan_actions,
            "note": ("Simulation-based. Plan is handed to the existing "
                     "remediation engine (response.py / action_switch.py) for "
                     "gated execution; nothing is executed by this coordinator."),
        }

    def get_stats(self) -> dict:
        return {
            "component": "RemediationCoordinator",
            "plans_built": self.plan_count,
            "auto_dispatched": self.auto_dispatched,
            "gated_requests": self.gated_requests,
        }


if __name__ == "__main__":
    print("=" * 55)
    print("Watchdog Swarm — Remediation Coordinator (Swarm #2)")
    print("Simulation test")
    print("=" * 55)
    coord = RemediationCoordinator()

    demo_alerts = [
        {"type": "MALICIOUS_PICKLE_DETECTED", "severity": "CRITICAL", "gpu": 0},
        {"type": "GPUTHOR_PRECURSOR_PREDICTED", "severity": "WARNING", "gpu": 1},
        {"type": "COVERT_COMPUTE_ONSET_PREDICTED", "severity": "WARNING", "gpu": 1},
        {"type": "CORRELATED_INCIDENT", "severity": "CRITICAL", "gpu": 1,
         "incident": "COORDINATED_WEIGHT_TAMPER"},
    ]
    plan = coord.build_plan(demo_alerts)
    print(f"\nPlan: {plan['action_count']} actions "
          f"({plan['auto_dispatch_count']} auto, {plan['gated_request_count']} gated)")
    for a in plan["actions"]:
        print(f"  [{a['mode']}] GPU{a['target_gpu']} {a['action']} "
              f"(from {a['source_alert']}, forensics_first={a['forensics_first']})")
    print("\nStats:", coord.get_stats())
