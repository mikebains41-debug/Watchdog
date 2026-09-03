#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
storm_response_orchestrator.py -- Solar Storm Response: Orchestration,
Damage Assessment, and Bounded Autonomy
Part of Watchdog AI-Attack Detection Suite -- Extreme Environments.

The detection pieces exist (solar_storm_detectors, radiation_damage_detectors,
SDC suite, correlators). This module is the RESPONSE layer that runs them
as one sequence as a storm unfolds -- the "5 W's" turned into code:

STAGES
------
  PRE_STORM   (warning window, 20 min - hours before protons arrive)
              checkpoint critical state, enable TMR on critical workloads,
              raise SDC/SEU sensitivity, defer non-critical (gated)
  IN_STORM    live S-level tracking, corruption + latch-up watch, posture
              escalation as the level climbs
  URGENT      a latch-up fires -> evacuate the workload, power-cycle the
              part (the ONE time-critical action: fast = chip survives,
              slow = chip burns out)
  POST_STORM  damage assessment: what hit, what was affected, which
              results are suspect, chip life consumed; re-verification
              list; evidence package

COMPONENTS
----------
1. StormResponseOrchestrator -- the stage machine. Consumes events from the
   detectors (warning, SPE, SDC, SEL, storm-ended) and drives the stages,
   emitting the actions for each. Everything disruptive is GATED, with one
   deliberate exception below.

2. PostStormDamageAssessment -- the Stage-4 report: peak S-level, duration,
   corruption events, latch-ups, dose consumed (krad and % of rating),
   suspect-result windows to re-verify, hardware to retire/derate.

3. BoundedAutonomyPolicy -- orbit-specific. Storms disrupt the polar
   ionosphere and HF comms, so ground control can be BLACKED OUT exactly
   when the latch-up response is needed. A latch-up left unattended burns
   out the chip. So: a PRE-AUTHORIZED, narrowly-bounded policy lets the
   urgent latch-up power-cycle proceed WITHOUT a live human ONLY when
   (a) comms are confirmed lost, (b) the action is on the pre-approved
   list, (c) it is reversible/non-destructive (power-cycle clears a
   latch-up, it does not damage), and (d) every autonomous action is
   logged for post-hoc review. Everything else stays gated even in
   blackout. This is the ONLY autonomy exception in Watchdog, and it is
   explicit, bounded, and auditable by design.

NOTE: Simulation/logic-tested. Requires real hardware validation. The
orchestration logic is real; orbital bounded autonomy has NOT been
exercised on a satellite. Not a shielding substitute -- detection +
response only.
"""

from datetime import datetime, timezone

STAGES = ("QUIET", "PRE_STORM", "IN_STORM", "URGENT", "POST_STORM")
S_RANK = {"S0": 0, "S1": 1, "S2": 2, "S3": 3, "S4": 4, "S5": 5}


# ---------------------------------------------------------------------------
# 3 -- Bounded autonomy policy (defined first; the orchestrator uses it)
# ---------------------------------------------------------------------------
class BoundedAutonomyPolicy:
    """
    The single, explicit autonomy exception. An action may run without a
    live human ONLY if ALL of:
      - comms_lost is True (ground control confirmed unreachable)
      - the action is on PRE_APPROVED (set at deployment, not at runtime)
      - the action is marked reversible/non-destructive
    Every autonomous decision is appended to an audit log.
    """

    # Actions that may run autonomously in blackout. Deliberately tiny.
    PRE_APPROVED = {
        "evacuate_workload_from_latched_part": {"reversible": True,
            "why": "moves work off a part; no data destroyed"},
        "power_cycle_latched_part": {"reversible": True,
            "why": "clears a latch-up; the part is not damaged by a cycle"},
        "checkpoint_critical_state": {"reversible": True, "why": "save-only"},
        "enable_tmr_on_critical_workloads": {"reversible": True, "why": "extra verification only"},
    }
    NEVER_AUTONOMOUS = {"delete_data", "wipe_keys", "deorbit", "permanent_shutdown",
                        "safe_hold_non_essential_hardware_gated", "pause_sensitive_workloads_gated"}

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.audit_log = []

    def authorize(self, action: str, comms_lost: bool, context: str = "") -> dict:
        ts = datetime.now(timezone.utc).isoformat()
        decision = {"action": action, "comms_lost": comms_lost, "timestamp": ts,
                    "context": context}
        if not self.enabled:
            decision.update(authorized=False, mode="gated",
                            reason="bounded autonomy disabled at deployment")
        elif action in self.NEVER_AUTONOMOUS:
            decision.update(authorized=False, mode="gated",
                            reason="action is on the NEVER_AUTONOMOUS list")
        elif not comms_lost:
            decision.update(authorized=False, mode="gated",
                            reason="comms available -> human decides")
        elif action not in self.PRE_APPROVED:
            decision.update(authorized=False, mode="gated",
                            reason="action not pre-approved for blackout autonomy")
        else:
            decision.update(authorized=True, mode="autonomous_bounded",
                            reason=self.PRE_APPROVED[action]["why"])
        self.audit_log.append(decision)
        return decision


# ---------------------------------------------------------------------------
# 1 -- Storm response orchestrator
# ---------------------------------------------------------------------------
class StormResponseOrchestrator:
    """
    Drives the stage machine from detector events. Call handle(event) with
    dicts from the detectors (they carry 'type'/'swarm_signal'). Returns the
    stage transition + the actions for that stage.
    """

    def __init__(self, autonomy: BoundedAutonomyPolicy = None):
        self.stage = "QUIET"
        self.peak_level = "S0"
        self.current_level = "S0"
        self.storm_started = None
        self.storm_ended = None
        self.comms_lost = False
        self.autonomy = autonomy or BoundedAutonomyPolicy(enabled=False)
        self.events = []          # every event seen during the storm
        self.actions_issued = []  # every action emitted
        self.corruption_events = 0
        self.latchup_events = 0

    def set_comms(self, lost: bool):
        self.comms_lost = bool(lost)

    def _emit(self, action: str, mode: str, detail: str, urgent=False) -> dict:
        a = {"action": action, "mode": mode, "detail": detail, "urgent": urgent,
             "stage": self.stage, "timestamp": datetime.now(timezone.utc).isoformat()}
        self.actions_issued.append(a)
        return a

    def _gated_or_autonomous(self, action: str, detail: str, urgent=False) -> dict:
        auth = self.autonomy.authorize(action, self.comms_lost, context=self.stage)
        mode = "autonomous_bounded" if auth["authorized"] else "gated_approval_request"
        a = self._emit(action, mode, detail, urgent=urgent)
        a["autonomy_decision"] = auth
        return a

    def handle(self, event: dict) -> dict:
        etype = event.get("swarm_signal") or event.get("type")
        self.events.append({"type": etype, "t": datetime.now(timezone.utc).isoformat()})
        prev = self.stage
        actions = []

        # ---- PRE_STORM: a warning arrived before flux -----------------------
        if etype == "SOLAR_STORM_WARNING" and self.stage in ("QUIET",):
            self.stage = "PRE_STORM"
            self.storm_started = self.storm_started or datetime.now(timezone.utc).isoformat()
            actions += [
                self._emit("checkpoint_critical_state", "auto_safe",
                           "save state before protons arrive (warning window)"),
                self._emit("enable_tmr_on_critical_workloads", "auto_safe",
                           "triple-run + majority-vote critical work; single bit-flips get outvoted"),
                self._emit("raise_sdc_seu_monitor_sensitivity", "auto_safe",
                           "watch harder for corruption"),
                self._gated_or_autonomous("defer_non_critical_compute",
                                          "reduce exposure during the window"),
            ]

        # ---- IN_STORM: flux is here / storm ongoing ------------------------
        elif etype in ("SOLAR_PARTICLE_EVENT", "SOLAR_STORM_ALERT", "SOLAR_STORM_ONGOING"):
            level = event.get("s_level") or event.get("expected_level") or "S1"
            self.current_level = level
            if S_RANK.get(level, 0) > S_RANK.get(self.peak_level, 0):
                self.peak_level = level
            if self.stage in ("QUIET", "PRE_STORM"):
                self.storm_started = self.storm_started or datetime.now(timezone.utc).isoformat()
                if self.stage == "QUIET":
                    # no warning was used -- do the pre-storm actions now, late
                    actions += [
                        self._emit("checkpoint_critical_state", "auto_safe",
                                   "LATE checkpoint: storm arrived without a used warning"),
                        self._emit("enable_tmr_on_critical_workloads", "auto_safe",
                                   "enable verification now"),
                    ]
            self.stage = "IN_STORM"
            actions.append(self._emit("raise_sdc_seu_monitor_sensitivity", "auto_safe",
                                      f"storm at {level}; corruption watch active"))
            if S_RANK.get(level, 0) >= 4:
                actions.append(self._gated_or_autonomous(
                    "pause_sensitive_workloads_gated",
                    f"{level}: reduce exposure of sensitive work (never autonomous)"))

        # ---- corruption during the storm ------------------------------------
        elif etype in ("SDC_CORRUPTION_DETECTED", "ECC_BREAK_SUSPECTED") and self.stage in ("IN_STORM", "URGENT"):
            self.corruption_events += 1
            actions.append(self._emit("flag_results_window_suspect", "auto_safe",
                                      "results computed in this window need re-verification"))

        # ---- URGENT: latch-up ----------------------------------------------
        elif etype == "SEL_LATCHUP_SUSPECTED":
            self.latchup_events += 1
            self.stage = "URGENT"
            actions += [
                self._gated_or_autonomous("evacuate_workload_from_latched_part",
                                          "move work off the latched part FIRST", urgent=True),
                self._gated_or_autonomous("power_cycle_latched_part",
                                          "power-cycle clears the latch-up; fast = chip survives, "
                                          "slow = burn-out", urgent=True),
            ]

        # ---- POST_STORM ------------------------------------------------------
        elif etype == "SOLAR_STORM_ENDED":
            self.stage = "POST_STORM"
            self.storm_ended = datetime.now(timezone.utc).isoformat()
            actions += [
                self._emit("run_post_storm_damage_assessment", "auto_safe",
                           "compute dose consumed, corruption count, suspect windows"),
                self._emit("reverify_suspect_results", "auto_safe",
                           "re-run / TMR-check results flagged during the storm"),
                self._emit("post_trip_health_verification", "auto_safe",
                           "verify each part before returning it to the pool"),
                self._emit("generate_evidence_package", "auto_safe",
                           "audit trail of the event and the response"),
            ]

        return {
            "type": "STORM_RESPONSE",
            "event": etype,
            "stage_before": prev,
            "stage_after": self.stage,
            "transitioned": prev != self.stage,
            "current_level": self.current_level,
            "peak_level": self.peak_level,
            "comms_lost": self.comms_lost,
            "actions": actions,
            "agent": "StormResponseOrchestrator",
            "gating_note": ("disruptive actions are gated; the ONLY autonomy exception is "
                            "the pre-approved, reversible latch-up response during a "
                            "confirmed comms blackout, and every such decision is logged"),
        }

    def summary(self) -> dict:
        return {"stage": self.stage, "peak_level": self.peak_level,
                "storm_started": self.storm_started, "storm_ended": self.storm_ended,
                "corruption_events": self.corruption_events,
                "latchup_events": self.latchup_events,
                "actions_issued": len(self.actions_issued),
                "autonomous_actions": sum(1 for a in self.actions_issued
                                          if a["mode"] == "autonomous_bounded")}


# ---------------------------------------------------------------------------
# 2 -- Post-storm damage assessment
# ---------------------------------------------------------------------------
class PostStormDamageAssessment:
    """
    The Stage-4 report. Inputs are the orchestrator summary plus the dose
    accumulator's before/after readings and the list of suspect windows.
    """

    def build(self, orchestrator_summary: dict, dose_before_krad: float,
              dose_after_krad: float, rated_krad: float,
              suspect_windows: list = None, latched_parts: list = None) -> dict:
        consumed = max(0.0, dose_after_krad - dose_before_krad)
        frac_after = (dose_after_krad / rated_krad) if rated_krad > 0 else 0.0
        life_consumed_pct = (consumed / rated_krad * 100.0) if rated_krad > 0 else 0.0

        # hardware disposition
        if frac_after >= 1.0:
            disposition = "RETIRE"
        elif frac_after >= 0.9:
            disposition = "DERATE_AND_SCHEDULE_REPLACEMENT"
        elif frac_after >= 0.75:
            disposition = "MONITOR_CLOSELY"
        else:
            disposition = "RETURN_TO_SERVICE_AFTER_VERIFICATION"

        severity = ("CRITICAL" if disposition == "RETIRE" or (latched_parts or [])
                    else "WARNING" if orchestrator_summary.get("corruption_events", 0) else "INFO")

        return {
            "type": "POST_STORM_DAMAGE_ASSESSMENT",
            "severity": severity,
            "what_hit": {
                "peak_s_level": orchestrator_summary.get("peak_level"),
                "storm_started": orchestrator_summary.get("storm_started"),
                "storm_ended": orchestrator_summary.get("storm_ended"),
            },
            "what_was_affected": {
                "corruption_events": orchestrator_summary.get("corruption_events", 0),
                "latchup_events": orchestrator_summary.get("latchup_events", 0),
                "latched_parts": latched_parts or [],
            },
            "dose": {
                "before_krad": round(dose_before_krad, 4),
                "after_krad": round(dose_after_krad, 4),
                "consumed_krad": round(consumed, 4),
                "rated_krad": rated_krad,
                "fraction_of_rating_after": round(frac_after, 4),
                "life_consumed_by_storm_pct": round(life_consumed_pct, 2),
            },
            "suspect_result_windows": suspect_windows or [],
            "reverification_required": bool(suspect_windows) or orchestrator_summary.get("corruption_events", 0) > 0,
            "hardware_disposition": disposition,
            "response_summary": {
                "actions_issued": orchestrator_summary.get("actions_issued", 0),
                "autonomous_actions": orchestrator_summary.get("autonomous_actions", 0),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "PostStormDamageAssessment",
            "note": ("Simulation-based. Dose figures from the TID accumulator; "
                     "disposition thresholds (75/90/100%) mirror the accumulator's "
                     "warn fractions. Not a shielding substitute."),
        }


if __name__ == "__main__":
    # A full storm with comms blackout during the latch-up.
    pol = BoundedAutonomyPolicy(enabled=True)
    orch = StormResponseOrchestrator(autonomy=pol)
    print("[1] warning ->", orch.handle({"swarm_signal": "SOLAR_STORM_WARNING"})["stage_after"])
    print("[2] S3 arrives ->", orch.handle({"swarm_signal": "SOLAR_PARTICLE_EVENT", "s_level": "S3"})["stage_after"])
    orch.handle({"type": "SDC_CORRUPTION_DETECTED"})
    orch.set_comms(lost=True)   # polar ionosphere blackout
    r = orch.handle({"swarm_signal": "SEL_LATCHUP_SUSPECTED"})
    print("[3] latch-up in blackout ->", r["stage_after"],
          [f"{a['action']}:{a['mode']}" for a in r["actions"]])
    orch.set_comms(lost=False)
    print("[4] ended ->", orch.handle({"swarm_signal": "SOLAR_STORM_ENDED"})["stage_after"])
    print("summary:", orch.summary())
    dmg = PostStormDamageAssessment().build(orch.summary(), 6.0, 8.1, 15.0,
                                            suspect_windows=["t1-t2"], latched_parts=["gpu2"])
    print("[5] assessment:", dmg["hardware_disposition"], "| life consumed:",
          dmg["dose"]["life_consumed_by_storm_pct"], "%")
