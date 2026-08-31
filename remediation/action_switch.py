#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
remediation/action_switch.py -- the Watchdog Switch

Per-action promotion registry. Every remediation action sits at one of
three trust levels, and an action can only move up on recorded evidence.

    DETECT_ONLY   -- never fires. Logs what it would have done.
    HUMAN_GATED   -- fires only with explicit approval per invocation.
    AUTO_FIRE     -- fires automatically. Requires proven-safe status.

WHY THIS EXISTS
    Today every action in remediation/response.py is gated the same way,
    globally, by two environment variables. Safe but blunt: an action
    proven to work a hundred times is treated exactly like one that has
    never executed. There is no path from "we built it" to "we trust it"
    short of flipping the global switch for everything at once.

PROMOTION RULES (deliberately conservative)
    DETECT_ONLY -> HUMAN_GATED   >= 1 recorded dry_run
    HUMAN_GATED -> AUTO_FIRE     >= min_successes real successes
                                 AND zero failures
                                 AND on the AUTO_FIRE_ELIGIBLE allowlist
    Any failure demotes one level immediately and resets the success
    count. Promotion is earned; demotion is instant.

NOT ELIGIBLE FOR AUTO_FIRE, EVER
    Actions that destroy state, evict tenants, or alter hardware power
    stay human-gated regardless of history. A hundred successes does not
    make an unrecoverable action safe to fire unattended.

HONEST LIMITS
    - Success history proves the action ran without error. It does not
      prove the action was correct, or that firing it was the right call.
    - Registry is local state; a fresh container starts from the
      persisted file, or DETECT_ONLY if there is none.
    - Nothing here overrides WD_DRY_RUN.
"""

import json
import os
import threading
from datetime import datetime, timezone

DETECT_ONLY = "DETECT_ONLY"
HUMAN_GATED = "HUMAN_GATED"
AUTO_FIRE = "AUTO_FIRE"
LEVELS = [DETECT_ONLY, HUMAN_GATED, AUTO_FIRE]

AUTO_FIRE_ELIGIBLE = {
    "log_alert",
    "emit_metric",
    "snapshot_telemetry",
    "tenant_file_scan",
}

NEVER_AUTO_FIRE = {
    "kill_process",
    "kubernetes_taint",
    "slurm_evict_job",
    "nvlink_disable",
    "gpu_memory_reset",
    "mig_quarantine",
    "tenant_file_clean",
    "power_limit_set",
}

DEFAULT_REGISTRY_PATH = os.environ.get(
    "WD_SWITCH_REGISTRY", "watchdog_action_switch.json")


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


class ActionSwitch:
    """Per-action trust registry with evidence-based promotion."""

    def __init__(self, registry_path=DEFAULT_REGISTRY_PATH,
                 min_successes=10, _open=open):
        self.registry_path = registry_path
        self.min_successes = min_successes
        self._open = _open
        self._lock = threading.Lock()
        self._actions = {}
        self._load()

    def _load(self):
        try:
            with self._open(self.registry_path) as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._actions = data.get("actions", {})
        except (FileNotFoundError, json.JSONDecodeError, OSError,
                PermissionError):
            self._actions = {}

    def _save(self):
        try:
            with self._open(self.registry_path, "w") as fh:
                json.dump({"updated": _now_iso(),
                           "actions": self._actions}, fh, indent=2)
            return True
        except (OSError, PermissionError):
            return False

    def _entry(self, action):
        if action not in self._actions:
            self._actions[action] = {
                "level": DETECT_ONLY, "successes": 0, "failures": 0,
                "dry_runs": 0, "last_result": None,
                "last_change": _now_iso(), "history": [],
            }
        return self._actions[action]

    def level(self, action):
        with self._lock:
            return self._entry(action)["level"]

    def status(self, action=None):
        with self._lock:
            if action is not None:
                e = dict(self._entry(action))
                e["auto_fire_eligible"] = action in AUTO_FIRE_ELIGIBLE
                e["never_auto_fire"] = action in NEVER_AUTO_FIRE
                e["promotable_to"] = self._next_level_if_earned(action)
                return e
            return {
                "registry_path": self.registry_path,
                "min_successes_for_auto": self.min_successes,
                "actions": dict(self._actions),
            }

    def should_fire(self, action, approval_granted_fn=None,
                    global_dry_run=None):
        """Return (bool fire, str reason). Never fires under dry-run."""
        if global_dry_run is None:
            global_dry_run = (
                os.environ.get("WD_DRY_RUN", "true").lower() != "false")
        if global_dry_run:
            return False, "GLOBAL_DRY_RUN"

        lvl = self.level(action)

        if lvl == DETECT_ONLY:
            return False, "DETECT_ONLY_NOT_PROMOTED"

        if lvl == HUMAN_GATED:
            if approval_granted_fn is None:
                return False, "HUMAN_GATED_NO_APPROVAL_FN"
            if approval_granted_fn(action):
                return True, "HUMAN_APPROVED"
            return False, "HUMAN_GATED_AWAITING_APPROVAL"

        if lvl == AUTO_FIRE:
            if action not in AUTO_FIRE_ELIGIBLE:
                return False, "AUTO_FIRE_NOT_ELIGIBLE_REFUSED"
            return True, "AUTO_FIRE_PROVEN_SAFE"

        return False, f"UNKNOWN_LEVEL_{lvl}"

    def record(self, action, outcome, detail=None):
        """outcome: 'success' | 'failure' | 'dry_run'. Returns new level."""
        with self._lock:
            e = self._entry(action)
            e["last_result"] = outcome
            e["history"].append({
                "ts": _now_iso(), "outcome": outcome, "detail": detail})
            e["history"] = e["history"][-100:]

            if outcome == "dry_run":
                e["dry_runs"] += 1
            elif outcome == "success":
                e["successes"] += 1
            elif outcome == "failure":
                e["failures"] += 1
                idx = LEVELS.index(e["level"])
                if idx > 0:
                    e["level"] = LEVELS[idx - 1]
                    e["last_change"] = _now_iso()
                e["successes"] = 0
                self._save()
                return e["level"]

            earned = self._next_level_if_earned(action)
            if earned and earned != e["level"]:
                e["level"] = earned
                e["last_change"] = _now_iso()
            self._save()
            return e["level"]

    def _next_level_if_earned(self, action):
        e = self._actions.get(action)
        if e is None:
            return DETECT_ONLY
        if e["failures"] > 0 and e["successes"] == 0:
            return DETECT_ONLY
        if e["level"] == DETECT_ONLY:
            return HUMAN_GATED if e["dry_runs"] >= 1 else DETECT_ONLY
        if e["level"] == HUMAN_GATED:
            if action in NEVER_AUTO_FIRE:
                return HUMAN_GATED
            if action not in AUTO_FIRE_ELIGIBLE:
                return HUMAN_GATED
            if e["successes"] >= self.min_successes and e["failures"] == 0:
                return AUTO_FIRE
            return HUMAN_GATED
        return e["level"]

    def force_level(self, action, level, reason):
        """Operator override. Requires a reason -- an override with no
        recorded justification is not auditable."""
        if level not in LEVELS:
            raise ValueError(f"unknown level: {level}")
        if level == AUTO_FIRE and action not in AUTO_FIRE_ELIGIBLE:
            raise ValueError(
                f"{action} is not AUTO_FIRE eligible -- refusing override")
        if not reason or not str(reason).strip():
            raise ValueError("force_level requires a reason")
        with self._lock:
            e = self._entry(action)
            e["level"] = level
            e["last_change"] = _now_iso()
            e["history"].append({
                "ts": _now_iso(), "outcome": "forced",
                "detail": f"forced to {level}: {reason}"})
            self._save()
            return level


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Watchdog action switch")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--action", default=None)
    args = ap.parse_args()
    sw = ActionSwitch()
    print(json.dumps(sw.status(args.action) if args.action
                     else sw.status(), indent=2))
