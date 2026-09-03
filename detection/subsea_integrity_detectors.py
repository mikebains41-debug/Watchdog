#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
subsea_integrity_detectors.py -- Subsea Data-Center Integrity Layer
Part of Watchdog AI-Attack Detection Suite -- Extreme Environments.

The subsea analog of the radiation-damage layer. Underwater, the physical
threats to compute are NOT radiation (the water column shields it) -- they
are PRESSURE, WATER INGRESS, and COOLING LOSS. This module implements the
three detectors that run on sensor telemetry that exists in any sealed
pressure vessel today (strain gauges, bilge/humidity sensors, hull-vs-
water temperature), so they are buildable and testable now.

  1. HullPressureMarginMonitor -- hydrostatic load vs. critical buckling
     pressure, with a margin that degrades as corrosion thins the hull.
     Physics: P_hydro = P_atm + rho*g*z ; P_crit = E/(2(1-nu^2)) * (t/r)^3.
     Buckling resistance scales with the CUBE of thickness/radius, so
     modest corrosion thinning eats margin fast. (UNDERWATER_DC modules
     11/12/106/116.)

  2. SeawaterIngressDetector -- the subsea "VRAM residual": a slow seal
     weep is the failure that kills a sealed vessel. Detects rising bilge
     level, rising internal humidity toward dew point, and falling
     penetrator insulation resistance -- the three early signatures of
     water getting in. (modules 7/20/107/118.)

  3. CoolingDegradationDetector -- biofouling insulates the hull, so the
     SAME workload drives internal temperature higher over weeks. Tracks
     effective heat-transfer coefficient drift: U = Q / (A * dT). A falling
     U at constant load = fouling/cooling loss, before it becomes a thermal
     event. (modules 9/22/29/30.) This is the subsea cousin of Watchdog's
     terrestrial thermal work.

TERRESTRIAL VALUE: #2 and #3 apply to any liquid-cooled / immersion-cooled
data center (ingress into cold plates, fouling of heat exchangers) -- so
they are not subsea-only.

NOTE: Simulation/logic-tested. Requires real hardware validation. Nothing
has been submerged; thresholds derive from the stated physics and the
Microsoft Project Natick public results (~1/8 terrestrial failure rate in
a sealed N2 vessel), not from Watchdog measurement. Design-stage spec
lives in UNDERWATER_DC_MODULES_1-150.md; this is the first buildable slice.
"""

import math
import statistics
from datetime import datetime, timezone

RHO_SEA = 1025.0     # kg/m^3
G = 9.81
P_ATM = 101_325.0    # Pa
E_STEEL = 200e9      # Pa, marine steel
NU_STEEL = 0.3


def hydrostatic_pressure_pa(depth_m: float) -> float:
    return P_ATM + RHO_SEA * G * max(0.0, depth_m)


def critical_buckling_pressure_pa(thickness_m: float, radius_m: float,
                                  E=E_STEEL, nu=NU_STEEL) -> float:
    """Thin-walled cylinder elastic buckling pressure (long cylinder)."""
    if radius_m <= 0 or thickness_m <= 0:
        return 0.0
    return (E / (2.0 * (1.0 - nu ** 2))) * (thickness_m / radius_m) ** 3


# ---------------------------------------------------------------------------
# 1 -- hull pressure margin
# ---------------------------------------------------------------------------
class HullPressureMarginMonitor:
    """
    Tracks the safety margin between hydrostatic load and buckling
    capacity, using CURRENT wall thickness (which corrosion sensors /
    ultrasonic thickness gauges report) so the margin honestly degrades as
    the hull thins.
    """

    def __init__(self, radius_m: float, design_thickness_m: float,
                 warn_margin=2.0, critical_margin=1.3):
        self.radius = radius_m
        self.design_t = design_thickness_m
        self.warn_margin = warn_margin
        self.critical_margin = critical_margin

    def check(self, depth_m: float, current_thickness_m: float = None) -> dict:
        t = current_thickness_m if current_thickness_m is not None else self.design_t
        p_load = hydrostatic_pressure_pa(depth_m)
        p_crit = critical_buckling_pressure_pa(t, self.radius)
        margin = (p_crit / p_load) if p_load > 0 else float("inf")
        thinning_pct = 100.0 * (1.0 - t / self.design_t) if self.design_t > 0 else 0.0

        result = {
            "substrate": "subsea",
            "depth_m": depth_m,
            "hydrostatic_pa": round(p_load),
            "hydrostatic_bar": round(p_load / 1e5, 2),
            "buckling_pa": round(p_crit),
            "safety_margin": round(margin, 2),
            "wall_thickness_m": t,
            "thinning_pct": round(thinning_pct, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "HullPressureMarginMonitor",
            "cite": "thin-wall cylinder buckling; UNDERWATER_DC modules 11/12/106/116",
        }
        if margin <= self.critical_margin:
            result["type"] = "HULL_BUCKLING_RISK_CRITICAL"
            result["severity"] = "CRITICAL"
            result["swarm_signal"] = "HULL_BUCKLING_RISK_CRITICAL"
            result["recommended_action"] = {
                "action": "reduce_depth_or_retrieve_gated",
                "detail": "buckling margin critical; ascend/retrieve before failure",
                "risk": "gated"}
        elif margin <= self.warn_margin:
            result["type"] = "HULL_MARGIN_LOW"
            result["severity"] = "WARNING"
            result["swarm_signal"] = "HULL_MARGIN_LOW"
            result["recommended_action"] = {
                "action": "schedule_inspection", "risk": "advisory"}
        else:
            result["type"] = "HULL_NOMINAL"
            result["severity"] = "INFO"
        return result


# ---------------------------------------------------------------------------
# 2 -- seawater ingress
# ---------------------------------------------------------------------------
class SeawaterIngressDetector:
    """
    Three independent early signatures of water getting in; any one is a
    WARNING, two or more together is CRITICAL (corroborated ingress).
      - bilge level rising (mm) over the window
      - internal relative humidity climbing toward the dew point
      - penetrator insulation resistance falling (saltwater weeping in)
    """

    def __init__(self, bilge_rise_mm_threshold=2.0, humidity_dewpoint_margin_c=3.0,
                 insulation_drop_pct_threshold=20.0, window=10):
        self.bilge_thr = bilge_rise_mm_threshold
        self.dew_margin = humidity_dewpoint_margin_c
        self.ins_drop_thr = insulation_drop_pct_threshold
        self.window = window
        self._bilge = []
        self._ins = []

    def update(self, bilge_level_mm: float, internal_temp_c: float,
               dew_point_c: float, penetrator_insulation_mohm: float) -> dict:
        self._bilge.append(float(bilge_level_mm))
        self._ins.append(float(penetrator_insulation_mohm))
        if len(self._bilge) > self.window:
            self._bilge.pop(0); self._ins.pop(0)

        signals = []
        if len(self._bilge) >= 2 and (self._bilge[-1] - self._bilge[0]) >= self.bilge_thr:
            signals.append("BILGE_RISING")
        if (internal_temp_c - dew_point_c) <= self.dew_margin:
            signals.append("CONDENSATION_IMMINENT")
        if len(self._ins) >= 2 and self._ins[0] > 0:
            drop_pct = 100.0 * (self._ins[0] - self._ins[-1]) / self._ins[0]
            if drop_pct >= self.ins_drop_thr:
                signals.append("PENETRATOR_INSULATION_FALLING")

        result = {
            "substrate": "subsea",
            "signals": signals,
            "bilge_mm": bilge_level_mm,
            "temp_minus_dewpoint_c": round(internal_temp_c - dew_point_c, 2),
            "insulation_mohm": penetrator_insulation_mohm,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "SeawaterIngressDetector",
            "cite": "UNDERWATER_DC modules 7/20/107/118; Project Natick sealed-vessel results",
        }
        if len(signals) >= 2:
            result["type"] = "SEAWATER_INGRESS_CONFIRMED"
            result["severity"] = "CRITICAL"
            result["swarm_signal"] = "SEAWATER_INGRESS_CONFIRMED"
            result["recommended_action"] = {
                "action": "isolate_power_paths_and_retrieve_gated",
                "detail": "corroborated ingress; cut exposed power paths, plan retrieval",
                "risk": "gated"}
        elif signals:
            result["type"] = "SEAWATER_INGRESS_SUSPECTED"
            result["severity"] = "WARNING"
            result["swarm_signal"] = "SEAWATER_INGRESS_SUSPECTED"
        else:
            result["type"] = "VESSEL_DRY"
            result["severity"] = "INFO"
        return result


# ---------------------------------------------------------------------------
# 3 -- cooling degradation (biofouling)
# ---------------------------------------------------------------------------
class CoolingDegradationDetector:
    """
    U = Q / (A * dT). Seal the baseline U at commissioning (clean hull).
    As biofouling accumulates, U falls: the same heat needs a bigger dT to
    reject, so internals run hotter at constant load. Flags a sustained U
    drop before it becomes a thermal event.
    """

    def __init__(self, hull_area_m2: float, warn_drop_pct=20.0, critical_drop_pct=40.0,
                 window=10):
        self.area = hull_area_m2
        self.warn = warn_drop_pct
        self.critical = critical_drop_pct
        self.window = window
        self._baseline_u = None
        self._recent_u = []

    @staticmethod
    def _u(heat_w: float, area_m2: float, hull_temp_c: float, water_temp_c: float):
        dT = hull_temp_c - water_temp_c
        if area_m2 <= 0 or dT <= 0:
            return None
        return heat_w / (area_m2 * dT)

    def seal_baseline(self, heat_w: float, hull_temp_c: float, water_temp_c: float) -> dict:
        u = self._u(heat_w, self.area, hull_temp_c, water_temp_c)
        self._baseline_u = u
        return {"type": "COOLING_BASELINE_SEALED" if u else "COOLING_BASELINE_FAILED",
                "baseline_u_w_per_m2k": None if u is None else round(u, 3)}

    def update(self, heat_w: float, hull_temp_c: float, water_temp_c: float) -> dict:
        result = {"substrate": "subsea",
                  "timestamp": datetime.now(timezone.utc).isoformat(),
                  "agent": "CoolingDegradationDetector",
                  "cite": "U=Q/(A*dT); UNDERWATER_DC modules 9/22/29/30"}
        if self._baseline_u is None:
            result["type"] = "COOLING_UNSEALED"
            result["severity"] = "INFO"
            return result
        u = self._u(heat_w, self.area, hull_temp_c, water_temp_c)
        if u is None:
            result["type"] = "COOLING_INVALID_SAMPLE"
            result["severity"] = "INFO"
            return result
        self._recent_u.append(u)
        if len(self._recent_u) > self.window:
            self._recent_u.pop(0)
        recent = statistics.fmean(self._recent_u)
        drop_pct = 100.0 * (self._baseline_u - recent) / self._baseline_u

        result.update({"baseline_u": round(self._baseline_u, 3),
                       "recent_u": round(recent, 3),
                       "u_drop_pct": round(drop_pct, 2)})
        if drop_pct >= self.critical:
            result["type"] = "COOLING_DEGRADATION_CRITICAL"
            result["severity"] = "CRITICAL"
            result["swarm_signal"] = "COOLING_DEGRADATION_CRITICAL"
            result["recommended_action"] = {
                "action": "throttle_workload_and_schedule_hull_cleaning",
                "detail": "heat-transfer coefficient collapsed (fouling); throttle + clean",
                "risk": "gated"}
        elif drop_pct >= self.warn:
            result["type"] = "COOLING_DEGRADATION_WARNING"
            result["severity"] = "WARNING"
            result["swarm_signal"] = "COOLING_DEGRADATION_WARNING"
            result["recommended_action"] = {"action": "schedule_hull_cleaning", "risk": "advisory"}
        else:
            result["type"] = "COOLING_NOMINAL"
            result["severity"] = "INFO"
        return result


if __name__ == "__main__":
    hull = HullPressureMarginMonitor(radius_m=1.5, design_thickness_m=0.05)
    print("[HULL] 150m clean:", hull.check(150.0)["type"],
          "| corroded 40%:", hull.check(150.0, current_thickness_m=0.03)["type"])
    ing = SeawaterIngressDetector()
    r = None
    for i in range(6):
        r = ing.update(bilge_level_mm=i * 0.6, internal_temp_c=22.0 - i * 0.5,
                       dew_point_c=20.0, penetrator_insulation_mohm=1000 - i * 60)
    print("[INGRESS]", r["type"], r["signals"])
    cool = CoolingDegradationDetector(hull_area_m2=40.0)
    cool.seal_baseline(heat_w=200_000, hull_temp_c=30.0, water_temp_c=10.0)
    last = None
    for i in range(6):
        last = cool.update(heat_w=200_000, hull_temp_c=30.0 + i * 3.0, water_temp_c=10.0)
    print("[COOLING]", last["type"], "drop", last["u_drop_pct"], "%")
