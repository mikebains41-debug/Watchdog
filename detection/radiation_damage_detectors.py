#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
radiation_damage_detectors.py -- Radiation-Damage Layer (SEL + TID)
Part of Watchdog AI-Attack Detection Suite -- Extreme Environments.

Completes the radiation-damage detection layer. Radiation causes THREE
distinct failures in electronics; Watchdog now covers all three at the
detection layer:

  1. SEU / bit-flip  -> a silently WRONG ANSWER.
                        ALREADY BUILT: SDC suite (Dr. DNA, nullification/
                        NaN cascade), ECC-break detector.
  2. SEL / latch-up  -> a CURRENT SPIKE that can physically burn out the
                        chip. THIS MODULE (SingleEventLatchupDetector).
  3. TID / dose      -> CUMULATIVE damage that degrades the chip over its
                        life. THIS MODULE (TotalIonizingDoseAccumulator).

Both run on telemetry that EXISTS today (current/power draw; a dose-rate
feed), so they are buildable and testable now. They are honestly labelled
as the radiation-damage layer that extends to orbit -- the orbital-ONLY
pieces (orbital-position correlation, Van Allen transit, eclipse timing)
need a satellite and remain design-stage in SPACE_DC_MODULES.

TERRESTRIAL VALUE (not just space)
----------------------------------
- SEL detection doubles as a power-fault / current-anomaly detector on any
  GPU (a sudden current spike is a fault signature regardless of cause).
- TID accumulation is the radiation analog of silicon aging (BTI/HCI) --
  the same "degradation rises with exposure" model Watchdog's SDC research
  established. Cosmic-ray flux at ground level is small but nonzero; at
  high-altitude/polar sites it is 17-32% higher (research finding).

Research basis: Google Trillium TPU 67 MeV proton beam test (June 2026):
survived a 5-year-equivalent dose, no hard failures to 15 krad(Si), HBM
irregularities at ~3x mission dose, SEU rates orders of magnitude above
ground. Anatomy of SDC: multi-bit upsets dominate in orbit (>60%).
SPACE_DC_MODULES spec modules 39 (TID), 41 (SEL), 45 (dose rate), 51
(hardness margin).

NOTE: Simulation/logic-tested. Requires real hardware validation --
terrestrial SEL validation on a pod (induce a current transient); orbital
validation needs a satellite. Thresholds grounded in the cited research;
per-part calibration required.
"""

import statistics
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# SEL -- single-event latch-up detector
# ---------------------------------------------------------------------------
class SingleEventLatchupDetector:
    """
    A latch-up is a parasitic-thyristor state triggered by a heavy-ion
    strike: current jumps abruptly and STAYS elevated until power is cycled.
    Left alone it overheats and can destroy the part. The signature is the
    combination of:
      - an ABRUPT current/power step (not a gradual workload ramp)
      - that PERSISTS (does not return to baseline)
      - with NO corresponding utilization increase (the workload didn't
        change -- the silicon did).
    That third condition is what distinguishes a latch-up from a legitimate
    burst of work, and it is exactly the signal Watchdog already has
    (power vs utilization).

    Detection is on a sliding window of (current_or_power, utilization)
    samples. Works on GPU power draw (W) or a direct current feed (A).
    """

    def __init__(self, gpu_id=0, window=20, step_ratio=1.5,
                 persist_samples=5, util_change_max_pct=10.0):
        self.gpu_id = gpu_id
        self.window = window
        self.step_ratio = step_ratio            # spike must be >= 1.5x baseline
        self.persist_samples = persist_samples  # and stay elevated this long
        self.util_change_max_pct = util_change_max_pct
        self._power = []
        self._util = []
        self.checks = 0
        self.flags = 0

    def update(self, power_or_current: float, util_pct: float,
               timestamp: str = None) -> dict:
        self.checks += 1
        self._power.append(float(power_or_current))
        self._util.append(float(util_pct))
        if len(self._power) > self.window:
            self._power.pop(0)
            self._util.pop(0)

        result = {
            "substrate": "gpu",
            "gpu_id": self.gpu_id,
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "agent": "SingleEventLatchupDetector",
        }

        need = self.persist_samples + 3
        if len(self._power) < need:
            result["type"] = "SEL_WARMING_UP"
            result["severity"] = "INFO"
            return result

        # baseline = samples before the recent persist window
        baseline_p = self._power[:-self.persist_samples]
        recent_p = self._power[-self.persist_samples:]
        baseline_u = self._util[:-self.persist_samples]
        recent_u = self._util[-self.persist_samples:]

        base_mean = statistics.fmean(baseline_p)
        recent_min = min(recent_p)
        base_util = statistics.fmean(baseline_u)
        recent_util = statistics.fmean(recent_u)

        # abrupt + persistent: EVERY recent sample above step_ratio x baseline
        abrupt_persistent = base_mean > 0 and recent_min >= self.step_ratio * base_mean
        # no matching workload change
        util_flat = abs(recent_util - base_util) <= self.util_change_max_pct

        result.update({
            "baseline_power": round(base_mean, 2),
            "recent_min_power": round(recent_min, 2),
            "step_ratio_observed": round(recent_min / base_mean, 2) if base_mean else None,
            "baseline_util": round(base_util, 1),
            "recent_util": round(recent_util, 1),
        })

        if abrupt_persistent and util_flat:
            self.flags += 1
            result["type"] = "SEL_LATCHUP_SUSPECTED"
            result["severity"] = "CRITICAL"
            result["swarm_signal"] = "SEL_LATCHUP_SUSPECTED"
            result["detail"] = ("abrupt, persistent current/power step with NO "
                                "matching utilization change -- silicon changed "
                                "state, workload did not (latch-up signature)")
            result["recommended_action"] = {
                "action": "power_cycle_affected_gpu_gated",
                "detail": ("latch-up clears only on power cycle; evacuate workload "
                           "then cycle. GATED -- a false positive here interrupts "
                           "a live workload; human confirms"),
                "risk": "gated"}
            result["cite"] = "SEL physics (parasitic thyristor); SPACE_DC module 41"
        elif abrupt_persistent and not util_flat:
            result["type"] = "POWER_STEP_WITH_WORKLOAD"
            result["severity"] = "INFO"
            result["detail"] = "power stepped up but utilization rose too -- legitimate burst"
        else:
            result["type"] = "SEL_NOMINAL"
            result["severity"] = "INFO"
        return result

    def get_stats(self):
        return {"component": "SingleEventLatchupDetector", "gpu_id": self.gpu_id,
                "checks": self.checks, "flags": self.flags}


# ---------------------------------------------------------------------------
# TID -- total ionizing dose accumulator
# ---------------------------------------------------------------------------
class TotalIonizingDoseAccumulator:
    """
    Integrates dose rate over time into cumulative dose and tracks the
    margin to the part's rated tolerance. Fires at configurable fractions of
    the rating so a mission/fleet can retire hardware BEFORE it fails.

    Calibration anchor (Google Trillium, June 2026): no hard failures to
    15 krad(Si); HBM irregularities appear at ~3x the mission dose. So a
    rated_tolerance_krad of ~15 with warnings at 50%/75%/90% is a defensible
    default for commercial accelerators; per-part values should override.

    dose_rate is in rad(Si)/hour; dt in hours. Terrestrial use: at ground
    level dose rate is tiny, so this mostly stays quiet -- which is the
    honest negative control.
    """

    def __init__(self, part_id="gpu0", rated_tolerance_krad=15.0,
                 warn_fractions=(0.50, 0.75, 0.90)):
        self.part_id = part_id
        self.rated_krad = rated_tolerance_krad
        self.warn_fractions = tuple(sorted(warn_fractions))
        self.cumulative_rad = 0.0
        self._fired = set()
        self.samples = 0

    def accumulate(self, dose_rate_rad_per_hr: float, dt_hours: float,
                   timestamp: str = None) -> dict:
        self.samples += 1
        self.cumulative_rad += max(0.0, float(dose_rate_rad_per_hr)) * max(0.0, float(dt_hours))
        cum_krad = self.cumulative_rad / 1000.0
        fraction = cum_krad / self.rated_krad if self.rated_krad > 0 else 0.0

        result = {
            "substrate": "gpu",
            "part_id": self.part_id,
            "cumulative_krad": round(cum_krad, 4),
            "rated_krad": self.rated_krad,
            "fraction_of_rating": round(fraction, 4),
            "remaining_margin_krad": round(self.rated_krad - cum_krad, 4),
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "agent": "TotalIonizingDoseAccumulator",
            "cite": ("Google Trillium 67 MeV proton test (Jun 2026): no hard fail "
                     "to 15 krad(Si); SPACE_DC modules 39/45/51"),
        }

        if fraction >= 1.0:
            result["type"] = "TID_RATING_EXCEEDED"
            result["severity"] = "CRITICAL"
            result["swarm_signal"] = "TID_RATING_EXCEEDED"
            result["recommended_action"] = {
                "action": "retire_part_migrate_workload_gated",
                "detail": "cumulative dose exceeds rated tolerance; retire/derate",
                "risk": "gated"}
            return result

        crossed = [f for f in self.warn_fractions if fraction >= f and f not in self._fired]
        if crossed:
            top = max(crossed)
            self._fired.update(crossed)
            result["type"] = "TID_THRESHOLD_CROSSED"
            result["severity"] = "WARNING" if top < 0.9 else "CRITICAL"
            result["threshold_fraction"] = top
            result["swarm_signal"] = "TID_THRESHOLD_CROSSED"
            result["recommended_action"] = {
                "action": "schedule_predictive_retirement",
                "detail": f"dose at {int(top*100)}% of rating; plan migration/replacement",
                "risk": "advisory"}
        else:
            result["type"] = "TID_NOMINAL"
            result["severity"] = "INFO"
        return result

    def get_stats(self):
        return {"component": "TotalIonizingDoseAccumulator", "part_id": self.part_id,
                "samples": self.samples, "cumulative_krad": round(self.cumulative_rad / 1000, 4),
                "thresholds_fired": sorted(self._fired)}


if __name__ == "__main__":
    # SEL demo: flat workload, then a persistent current step with no util change
    sel = SingleEventLatchupDetector(gpu_id=0)
    for _ in range(10):
        sel.update(300.0, 60.0)
    r = None
    for _ in range(6):
        r = sel.update(520.0, 60.0)   # 1.73x step, util unchanged
    print("[SEL]", r["type"])

    # TID demo: orbital-ish dose rate over a mission
    tid = TotalIonizingDoseAccumulator("gpu0", rated_tolerance_krad=15.0)
    last = None
    for hour in range(0, 20000, 100):
        last = tid.accumulate(dose_rate_rad_per_hr=0.9, dt_hours=100)
        if last["type"] != "TID_NOMINAL":
            print("[TID]", last["type"], "at", last["cumulative_krad"], "krad")
    print("[TID] final:", last["type"], tid.get_stats()["cumulative_krad"], "krad")
