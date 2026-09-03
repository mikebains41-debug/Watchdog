#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_storm_response.py

Tests the solar-storm RESPONSE layer: the stage machine (PRE_STORM ->
IN_STORM -> URGENT -> POST_STORM), the post-storm damage assessment, and
-- most carefully -- the bounded-autonomy policy: autonomy ONLY in a
confirmed comms blackout, ONLY for pre-approved reversible actions, NEVER
for destructive ones, always audited.

Run standalone: python3 tests/test_storm_response.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from intelligence.swarm.storm_response_orchestrator import (
    StormResponseOrchestrator, PostStormDamageAssessment, BoundedAutonomyPolicy,
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


def _actions(r):
    return [a["action"] for a in r["actions"]]


# --------------------------------------------------------------------------
# Stage machine
# --------------------------------------------------------------------------
def test_warning_enters_pre_storm_with_checkpoint_and_tmr():
    o = StormResponseOrchestrator()
    r = o.handle({"swarm_signal": "SOLAR_STORM_WARNING"})
    check("stage: WARNING -> PRE_STORM", r["stage_after"] == "PRE_STORM", f"got {r['stage_after']}")
    acts = _actions(r)
    check("stage: pre-storm issues checkpoint + TMR + sensitivity",
          {"checkpoint_critical_state", "enable_tmr_on_critical_workloads",
           "raise_sdc_seu_monitor_sensitivity"} <= set(acts), f"got {acts}")


def test_spe_enters_in_storm_and_tracks_peak():
    o = StormResponseOrchestrator()
    o.handle({"swarm_signal": "SOLAR_STORM_WARNING"})
    r = o.handle({"swarm_signal": "SOLAR_PARTICLE_EVENT", "s_level": "S2"})
    check("stage: SPE -> IN_STORM", r["stage_after"] == "IN_STORM", f"got {r['stage_after']}")
    o.handle({"swarm_signal": "SOLAR_STORM_ONGOING", "s_level": "S4"})
    o.handle({"swarm_signal": "SOLAR_STORM_ONGOING", "s_level": "S2"})
    check("stage: peak level tracked (S4 stays the peak after dropping to S2)",
          o.peak_level == "S4" and o.current_level == "S2", f"peak={o.peak_level} cur={o.current_level}")


def test_storm_without_warning_does_late_checkpoint():
    o = StormResponseOrchestrator()
    r = o.handle({"swarm_signal": "SOLAR_PARTICLE_EVENT", "s_level": "S1"})  # no warning first
    check("stage: storm arriving without a warning still checkpoints (late)",
          "checkpoint_critical_state" in _actions(r) and r["stage_after"] == "IN_STORM",
          f"got {_actions(r)}")


def test_s4_pauses_sensitive_gated():
    o = StormResponseOrchestrator()
    r = o.handle({"swarm_signal": "SOLAR_PARTICLE_EVENT", "s_level": "S4"})
    pause = [a for a in r["actions"] if a["action"] == "pause_sensitive_workloads_gated"]
    check("stage: S4 recommends pausing sensitive work, GATED",
          pause and pause[0]["mode"] == "gated_approval_request", f"got {pause}")


def test_corruption_flags_suspect_window():
    o = StormResponseOrchestrator()
    o.handle({"swarm_signal": "SOLAR_PARTICLE_EVENT", "s_level": "S2"})
    r = o.handle({"type": "SDC_CORRUPTION_DETECTED"})
    check("stage: SDC during storm -> flag results window suspect",
          "flag_results_window_suspect" in _actions(r) and o.corruption_events == 1, f"got {_actions(r)}")


def test_latchup_enters_urgent_with_evacuate_then_cycle():
    o = StormResponseOrchestrator()
    o.handle({"swarm_signal": "SOLAR_PARTICLE_EVENT", "s_level": "S3"})
    r = o.handle({"swarm_signal": "SEL_LATCHUP_SUSPECTED"})
    acts = _actions(r)
    check("stage: latch-up -> URGENT", r["stage_after"] == "URGENT", f"got {r['stage_after']}")
    check("stage: urgent = evacuate FIRST, then power-cycle",
          acts == ["evacuate_workload_from_latched_part", "power_cycle_latched_part"], f"got {acts}")
    check("stage: urgent actions are marked urgent", all(a["urgent"] for a in r["actions"]))


def test_storm_ended_enters_post_storm():
    o = StormResponseOrchestrator()
    o.handle({"swarm_signal": "SOLAR_PARTICLE_EVENT", "s_level": "S2"})
    r = o.handle({"swarm_signal": "SOLAR_STORM_ENDED"})
    acts = _actions(r)
    check("stage: ENDED -> POST_STORM with assessment + reverify + health check + evidence",
          r["stage_after"] == "POST_STORM" and
          {"run_post_storm_damage_assessment", "reverify_suspect_results",
           "post_trip_health_verification", "generate_evidence_package"} <= set(acts), f"got {acts}")


# --------------------------------------------------------------------------
# Bounded autonomy -- the careful part
# --------------------------------------------------------------------------
def test_autonomy_disabled_by_default():
    o = StormResponseOrchestrator()   # default policy: disabled
    o.set_comms(lost=True)
    r = o.handle({"swarm_signal": "SEL_LATCHUP_SUSPECTED"})
    check("autonomy: disabled by default -> latch-up response stays GATED even in blackout",
          all(a["mode"] == "gated_approval_request" for a in r["actions"]), f"got {r['actions']}")


def test_autonomy_requires_comms_lost():
    pol = BoundedAutonomyPolicy(enabled=True)
    o = StormResponseOrchestrator(autonomy=pol)
    o.set_comms(lost=False)   # ground control reachable
    r = o.handle({"swarm_signal": "SEL_LATCHUP_SUSPECTED"})
    check("autonomy: comms available -> GATED (human decides), not autonomous",
          all(a["mode"] == "gated_approval_request" for a in r["actions"]), f"got {r['actions']}")


def test_autonomy_fires_only_in_blackout_for_preapproved():
    pol = BoundedAutonomyPolicy(enabled=True)
    o = StormResponseOrchestrator(autonomy=pol)
    o.set_comms(lost=True)
    r = o.handle({"swarm_signal": "SEL_LATCHUP_SUSPECTED"})
    check("autonomy: blackout + pre-approved latch-up actions -> autonomous_bounded",
          all(a["mode"] == "autonomous_bounded" for a in r["actions"]), f"got {r['actions']}")
    check("autonomy: every autonomous decision is audited",
          len(pol.audit_log) == 2 and all(d["authorized"] for d in pol.audit_log), f"got {pol.audit_log}")


def test_autonomy_never_for_destructive_even_in_blackout():
    pol = BoundedAutonomyPolicy(enabled=True)
    for act in ("delete_data", "wipe_keys", "deorbit", "permanent_shutdown",
                "pause_sensitive_workloads_gated"):
        d = pol.authorize(act, comms_lost=True)
        check(f"autonomy: {act} NEVER autonomous even in blackout",
              not d["authorized"] and d["mode"] == "gated", f"got {d}")


def test_autonomy_unknown_action_gated():
    pol = BoundedAutonomyPolicy(enabled=True)
    d = pol.authorize("some_new_action", comms_lost=True)
    check("autonomy: an action not on the pre-approved list stays gated",
          not d["authorized"], f"got {d}")


def test_s4_pause_stays_gated_in_blackout():
    pol = BoundedAutonomyPolicy(enabled=True)
    o = StormResponseOrchestrator(autonomy=pol)
    o.set_comms(lost=True)
    r = o.handle({"swarm_signal": "SOLAR_PARTICLE_EVENT", "s_level": "S5"})
    pause = [a for a in r["actions"] if a["action"] == "pause_sensitive_workloads_gated"]
    check("autonomy: pausing workloads stays GATED even at S5 in blackout (only latch-up is autonomous)",
          pause and pause[0]["mode"] == "gated_approval_request", f"got {pause}")


# --------------------------------------------------------------------------
# Damage assessment
# --------------------------------------------------------------------------
def _run_storm(latch=True):
    pol = BoundedAutonomyPolicy(enabled=True)
    o = StormResponseOrchestrator(autonomy=pol)
    o.handle({"swarm_signal": "SOLAR_STORM_WARNING"})
    o.handle({"swarm_signal": "SOLAR_PARTICLE_EVENT", "s_level": "S3"})
    o.handle({"type": "SDC_CORRUPTION_DETECTED"})
    if latch:
        o.set_comms(lost=True)
        o.handle({"swarm_signal": "SEL_LATCHUP_SUSPECTED"})
        o.set_comms(lost=False)
    o.handle({"swarm_signal": "SOLAR_STORM_ENDED"})
    return o


def test_damage_assessment_full_report():
    o = _run_storm()
    dmg = PostStormDamageAssessment().build(o.summary(), dose_before_krad=6.0,
                                            dose_after_krad=8.1, rated_krad=15.0,
                                            suspect_windows=["t1-t2"], latched_parts=["gpu2"])
    check("damage: reports peak level, corruption + latch-up counts",
          dmg["what_hit"]["peak_s_level"] == "S3" and dmg["what_was_affected"]["corruption_events"] == 1
          and dmg["what_was_affected"]["latchup_events"] == 1, f"got {dmg}")
    check("damage: dose consumed = 2.1 krad = 14% of rating",
          dmg["dose"]["consumed_krad"] == 2.1 and abs(dmg["dose"]["life_consumed_by_storm_pct"] - 14.0) < 0.01,
          f"got {dmg['dose']}")
    check("damage: reverification required when corruption occurred",
          dmg["reverification_required"] is True)
    check("damage: latched part makes it CRITICAL", dmg["severity"] == "CRITICAL")


def test_damage_disposition_thresholds():
    o = _run_storm(latch=False)
    d = PostStormDamageAssessment()
    ret = d.build(o.summary(), 14.0, 15.5, 15.0)
    derate = d.build(o.summary(), 12.0, 14.0, 15.0)
    ok = d.build(o.summary(), 2.0, 3.0, 15.0)
    check("damage: dose past rating -> RETIRE", ret["hardware_disposition"] == "RETIRE", f"got {ret['hardware_disposition']}")
    check("damage: 90%+ -> DERATE_AND_SCHEDULE_REPLACEMENT",
          derate["hardware_disposition"] == "DERATE_AND_SCHEDULE_REPLACEMENT", f"got {derate['hardware_disposition']}")
    check("damage: low dose -> RETURN_TO_SERVICE_AFTER_VERIFICATION",
          ok["hardware_disposition"] == "RETURN_TO_SERVICE_AFTER_VERIFICATION", f"got {ok['hardware_disposition']}")


def test_summary_counts_autonomous_actions():
    o = _run_storm()
    s = o.summary()
    check("summary: autonomous actions counted (the 2 latch-up actions in blackout)",
          s["autonomous_actions"] == 2 and s["latchup_events"] == 1, f"got {s}")


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
