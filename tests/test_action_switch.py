#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_action_switch.py

Tests the Watchdog Switch. The important tests are the ceiling ones:
proving a destructive action cannot reach AUTO_FIRE no matter how clean
its history, and that a hand-edited registry file is still refused.

Run: python3 tests/test_action_switch.py
"""
import sys, os, json, tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from remediation.action_switch import (
    ActionSwitch, DETECT_ONLY, HUMAN_GATED, AUTO_FIRE,
    AUTO_FIRE_ELIGIBLE, NEVER_AUTO_FIRE)

PASSED, FAILED = [], []

def check(name, cond, detail=""):
    if cond:
        PASSED.append(name); print(f"[PASS] {name}")
    else:
        FAILED.append(name); print(f"[FAIL] {name} {detail}")

def sw():
    return ActionSwitch(registry_path=tempfile.mktemp(), min_successes=3)


def test_default_is_detect_only():
    check("DEFAULT: unknown action starts at DETECT_ONLY",
          sw().level("some_new_action") == DETECT_ONLY)


def test_detect_only_never_fires():
    fire, reason = sw().should_fire("log_alert", global_dry_run=False)
    check("DETECT_ONLY: refuses to fire",
          fire is False and reason == "DETECT_ONLY_NOT_PROMOTED",
          f"got {fire} {reason}")


def test_global_dry_run_blocks_everything():
    s = sw()
    s.force_level("log_alert", AUTO_FIRE, "test setup")
    fire, reason = s.should_fire("log_alert", global_dry_run=True)
    check("GLOBAL DRY_RUN: blocks even AUTO_FIRE actions",
          fire is False and reason == "GLOBAL_DRY_RUN", f"got {reason}")


def test_dry_run_promotes_to_human_gated():
    check("PROMOTION: one dry_run promotes DETECT_ONLY -> HUMAN_GATED",
          sw().record("log_alert", "dry_run") == HUMAN_GATED)


def test_human_gated_needs_approval():
    s = sw(); s.record("log_alert", "dry_run")
    fire, reason = s.should_fire("log_alert",
                                 approval_granted_fn=lambda a: False,
                                 global_dry_run=False)
    check("HUMAN_GATED: refuses without approval",
          fire is False and reason == "HUMAN_GATED_AWAITING_APPROVAL",
          f"got {reason}")
    fire, reason = s.should_fire("log_alert",
                                 approval_granted_fn=lambda a: True,
                                 global_dry_run=False)
    check("HUMAN_GATED: fires with approval",
          fire is True and reason == "HUMAN_APPROVED", f"got {reason}")


def test_successes_promote_to_auto_fire():
    s = sw(); s.record("log_alert", "dry_run")
    for _ in range(3):
        lvl = s.record("log_alert", "success")
    check("PROMOTION: 3 successes promote eligible action to AUTO_FIRE",
          lvl == AUTO_FIRE, f"got {lvl}")
    fire, reason = s.should_fire("log_alert", global_dry_run=False)
    check("AUTO_FIRE: fires without approval once proven",
          fire is True and reason == "AUTO_FIRE_PROVEN_SAFE", f"got {reason}")


def test_ineligible_action_never_reaches_auto_fire():
    s = sw(); s.record("kill_process", "dry_run")
    for _ in range(50):
        lvl = s.record("kill_process", "success")
    check("CEILING: kill_process stays HUMAN_GATED after 50 successes",
          lvl == HUMAN_GATED, f"got {lvl}")


def test_destructive_actions_on_never_list():
    missing = [a for a in ["kill_process", "kubernetes_taint",
                            "slurm_evict_job", "nvlink_disable",
                            "gpu_memory_reset", "tenant_file_clean"]
               if a not in NEVER_AUTO_FIRE]
    check("CEILING: all destructive actions on NEVER_AUTO_FIRE list",
          missing == [], f"missing {missing}")


def test_no_overlap_between_lists():
    overlap = AUTO_FIRE_ELIGIBLE & NEVER_AUTO_FIRE
    check("CEILING: no action is both eligible and never-eligible",
          overlap == set(), f"overlap {overlap}")


def test_failure_demotes_immediately():
    s = sw(); s.record("log_alert", "dry_run")
    for _ in range(3):
        s.record("log_alert", "success")
    check("DEMOTION: reached AUTO_FIRE first",
          s.level("log_alert") == AUTO_FIRE)
    check("DEMOTION: one failure drops AUTO_FIRE -> HUMAN_GATED",
          s.record("log_alert", "failure", detail="simulated") == HUMAN_GATED)


def test_failure_resets_success_count():
    s = sw(); s.record("log_alert", "dry_run")
    for _ in range(3):
        s.record("log_alert", "success")
    s.record("log_alert", "failure")
    check("DEMOTION: failure resets success count to 0",
          s.status("log_alert")["successes"] == 0)


def test_forced_auto_fire_refused_for_ineligible():
    try:
        sw().force_level("kill_process", AUTO_FIRE, "operator insists")
        check("OVERRIDE: refuses AUTO_FIRE for ineligible action", False,
              "no exception raised")
    except ValueError:
        check("OVERRIDE: refuses AUTO_FIRE for ineligible action", True)


def test_force_level_requires_reason():
    try:
        sw().force_level("log_alert", HUMAN_GATED, "")
        check("OVERRIDE: requires a reason", False, "no exception")
    except ValueError:
        check("OVERRIDE: requires a reason", True)


def test_hand_edited_registry_still_refused():
    """Defence in depth: even if the file says AUTO_FIRE for an
    ineligible action, should_fire must refuse."""
    p = tempfile.mktemp()
    with open(p, "w") as fh:
        json.dump({"actions": {"kill_process": {
            "level": AUTO_FIRE, "successes": 999, "failures": 0,
            "dry_runs": 1, "last_result": "success",
            "last_change": "x", "history": []}}}, fh)
    fire, reason = ActionSwitch(registry_path=p).should_fire(
        "kill_process", global_dry_run=False)
    check("DEFENCE: hand-edited AUTO_FIRE on ineligible action refused",
          fire is False and reason == "AUTO_FIRE_NOT_ELIGIBLE_REFUSED",
          f"got {fire} {reason}")
    os.remove(p)


def test_state_persists_across_instances():
    p = tempfile.mktemp()
    ActionSwitch(registry_path=p, min_successes=3).record(
        "log_alert", "dry_run")
    s2 = ActionSwitch(registry_path=p, min_successes=3)
    check("PERSISTENCE: level survives a new instance",
          s2.level("log_alert") == HUMAN_GATED)
    os.remove(p)


def test_history_is_bounded():
    s = sw()
    for _ in range(150):
        s.record("log_alert", "success")
    check("HISTORY: bounded to last 100 entries",
          len(s.status("log_alert")["history"]) == 100)


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_"):
            try:
                _f()
            except Exception as e:
                check(_n, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    for f in FAILED:
        print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
