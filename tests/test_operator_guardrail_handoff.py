#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_operator_guardrail_handoff.py  *** WATCHDOG ***

Tests the operator-agent guardrail adapter (external guardrail can only
tighten; Watchdog's floor never overridden; fail-closed on guardrail error)
and the recovery-system handoff adapter (destructive handoffs withheld
until approved; vocabulary mapping; unmapped actions routed to a human).
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from intelligence.swarm.operator_guardrail_and_handoff import (
    OperatorGuardrailAdapter, RecoveryHandoffAdapter, NEVER_ALLOWED,
)

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name}{'' if cond else ' ' + detail}")


class AllowAll:
    def scan(self, p): return {"decision": "ALLOW", "reason": "ok"}


class BlockAll:
    def scan(self, p): return {"decision": "BLOCK", "reason": "policy"}


class Boom:
    def scan(self, p): raise RuntimeError("guardrail crashed")


# ---- guardrail -------------------------------------------------------------
def test_fallback_when_llamafirewall_missing():
    g = OperatorGuardrailAdapter()
    r = g.load()
    check("guard: no llamafirewall here -> GUARDRAIL_FALLBACK, floor-only, error recorded",
          r["type"] == "GUARDRAIL_FALLBACK" and g.mode == "watchdog_floor_only" and r["load_error"], f"got {r}")


def test_auto_safe_allowed():
    g = OperatorGuardrailAdapter(guardrail=AllowAll())
    d = g.evaluate({"action": "checkpoint_critical_state", "target": "gpu0"})
    check("guard: auto-safe action -> ALLOW", d["decision"] == "ALLOW", f"got {d}")


def test_destructive_gated_without_approval():
    g = OperatorGuardrailAdapter(guardrail=AllowAll())
    d = g.evaluate({"action": "evacuate_workload", "target": "gpu0"})
    check("guard: destructive w/o approval -> GATE even if external guardrail says ALLOW",
          d["decision"] == "GATE" and d["external_guardrail"]["decision"] == "ALLOW", f"got {d}")


def test_destructive_allowed_with_approval():
    g = OperatorGuardrailAdapter(guardrail=AllowAll())
    d = g.evaluate({"action": "evacuate_workload", "target": "gpu0"}, human_approved=True)
    check("guard: destructive + human approval -> ALLOW", d["decision"] == "ALLOW", f"got {d}")


def test_never_allowed_even_with_approval_and_allow_guardrail():
    g = OperatorGuardrailAdapter(guardrail=AllowAll())
    for act in NEVER_ALLOWED:
        d = g.evaluate({"action": act, "target": "x"}, human_approved=True)
        check(f"guard: {act} -> BLOCK even with approval + permissive guardrail", d["decision"] == "BLOCK", f"got {d}")


def test_external_block_wins_over_floor_allow():
    g = OperatorGuardrailAdapter(guardrail=BlockAll())
    d = g.evaluate({"action": "checkpoint_critical_state", "target": "gpu0"})
    check("guard: external BLOCK tightens an auto-safe action to BLOCK", d["decision"] == "BLOCK", f"got {d}")


def test_guardrail_error_fails_closed():
    g = OperatorGuardrailAdapter(guardrail=Boom())
    d = g.evaluate({"action": "checkpoint_critical_state", "target": "gpu0"})
    check("guard: guardrail exception -> GATE (fail closed), error surfaced",
          d["decision"] == "GATE" and "RuntimeError" in d["external_guardrail"]["reason"], f"got {d}")


def test_unknown_action_gated():
    g = OperatorGuardrailAdapter(guardrail=AllowAll())
    d = g.evaluate({"action": "frobnicate_the_cluster", "target": "all"})
    check("guard: unknown action -> GATE by default", d["decision"] == "GATE", f"got {d}")


def test_floor_only_still_enforces():
    g = OperatorGuardrailAdapter()   # no external guardrail available
    g.load()
    d1 = g.evaluate({"action": "wipe_keys", "target": "vault"}, human_approved=True)
    d2 = g.evaluate({"action": "log", "target": "x"})
    check("guard: floor-only mode still BLOCKs never-allowed and ALLOWs auto-safe",
          d1["decision"] == "BLOCK" and d2["decision"] == "ALLOW", f"got {d1['decision']}, {d2['decision']}")


# ---- handoff ---------------------------------------------------------------
def _inc(action, sev="CRITICAL"):
    return {"incident": "DEGRADING_SILICON_INCIDENT", "severity": sev, "gpu_index": 2,
            "recommended_action": {"action": action, "risk": "gated"}}


def test_handoff_withheld_when_pending():
    h = RecoveryHandoffAdapter()
    r = h.build(_inc("schedule_gpu_out_and_preserve_evidence"), "pending")
    check("handoff: destructive recovery, gate pending -> WITHHELD",
          r["type"] == "RECOVERY_HANDOFF_WITHHELD" and h.withheld == 1, f"got {r}")


def test_handoff_withheld_when_denied():
    h = RecoveryHandoffAdapter()
    r = h.build(_inc("power_cycle_latched_part"), "denied")
    check("handoff: denied -> WITHHELD", r["type"] == "RECOVERY_HANDOFF_WITHHELD")


def test_handoff_emitted_when_approved():
    h = RecoveryHandoffAdapter()
    r = h.build(_inc("schedule_gpu_out_and_preserve_evidence"), "human_approved", evidence_ref="ledger:abc")
    check("handoff: approved -> RECOVERY_HANDOFF, action mapped to 'drain'",
          r["type"] == "RECOVERY_HANDOFF" and r["recovery_action"] == "drain" and r["ready_to_execute"], f"got {r}")
    check("handoff: CRITICAL -> urgency immediate, evidence ref carried",
          r["urgency"] == "immediate" and r["evidence_ref"] == "ledger:abc")


def test_handoff_vocabulary_mapping():
    h = RecoveryHandoffAdapter()
    m = {
        "evacuate_workload_from_latched_part": "migrate",
        "power_cycle_latched_part": "reset",
        "isolate_sandbox_and_raise_gated": "quarantine",
        "retire_part_migrate_workload_gated": "retire",
    }
    ok = all(h.build(_inc(a), "human_approved")["recovery_action"] == v for a, v in m.items())
    check("handoff: Watchdog actions map to recovery vocabulary (migrate/reset/quarantine/retire)", ok)


def test_handoff_auto_safe_passes_without_approval():
    h = RecoveryHandoffAdapter()
    r = h.build(_inc("checkpoint_critical_state", sev="WARNING"), "auto_safe")
    check("handoff: checkpoint (non-destructive) emitted with auto_safe, urgency scheduled",
          r["type"] == "RECOVERY_HANDOFF" and r["recovery_action"] == "checkpoint"
          and r["urgency"] == "scheduled", f"got {r}")


def test_handoff_unmapped_routes_to_human():
    h = RecoveryHandoffAdapter()
    r = h.build(_inc("some_novel_watchdog_action"), "human_approved")
    check("handoff: unmapped action -> UNMAPPED (human routes), not silently dropped",
          r["type"] == "RECOVERY_HANDOFF_UNMAPPED", f"got {r}")


def test_handoff_positioning_note():
    h = RecoveryHandoffAdapter()
    r = h.build(_inc("checkpoint_critical_state"), "auto_safe")
    check("handoff: states Watchdog detects/gates, recovery system executes",
          "recovery system executes" in r["positioning"])


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            try:
                fn()
            except Exception as e:
                check(name, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60 + f"\nPASSED: {len(PASSED)}   FAILED: {len(FAILED)}\n" + "=" * 60)
    sys.exit(1 if FAILED else 0)
