#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
solar_storm_detectors.py -- Solar Particle Event Detection & Storm Hardening
Part of Watchdog AI-Attack Detection Suite -- Extreme Environments.

THE GAP THIS FILLS
------------------
The radiation-damage layer (SDC, SEL, TID) REACTS to damage as it happens.
A solar storm is different: it is a forecastable EVENT with warning time.
A flare's light reaches Earth in ~8 min; the dangerous protons arrive
20 minutes to many hours later. That window is the opportunity: see the
storm coming and harden posture BEFORE the particles hit.

THE DATA (real, public, free)
-----------------------------
NOAA SWPC publishes GOES 5-minute-averaged integral proton flux as JSON.
Units: pfu = protons/(cm^2 s sr). The NOAA S-scale (Solar Radiation Storm)
is defined on the >=10 MeV integral flux:
    S1 minor    >= 10 pfu
    S2 moderate >= 100 pfu
    S3 strong   >= 1,000 pfu
    S4 severe   >= 10,000 pfu
    S5 extreme  >= 100,000 pfu   ("satellite systems may be rendered useless")
Plus a separate >=100 MeV alert at 1 pfu (the hard, penetrating protons).
Historic max: 43,500 pfu (March 1991). Example onset: 28 Oct 2003, ~2 pfu
-> >5,000 pfu within hours, S4 by midnight, ~12 h duration.
SEU rates in electronics rise directly with this flux -- so the flux IS
the bit-flip-risk forecast.

NOAA JSON format ('integral-protons' file): a list of records like
  {"time_tag": "2026-09-02T12:00:00Z", "flux": 2.1, "energy": ">=10 MeV", ...}
with energy thresholds >=1, >=5, >=10, >=30, >=50, >=60, >=100, >=500 MeV.

COMPONENTS
----------
1. SolarParticleEventDetector -- ingests NOAA-format proton-flux records,
   classifies the current S-level, and detects ONSET (flux rising orders of
   magnitude over background within a short window) -- the moment a storm
   begins, before it peaks.
2. SpaceWeatherWarningIngest -- reads NOAA Proton Event WARNING products
   ("expected ONSET"/"expected PERSISTENCE") to get the head start before
   flux is measured -- the early-warning window.
3. StormHardeningPosture -- given the S-level / a warning, RECOMMENDS
   (gated) the defensive posture for the window: checkpoint, raise
   verification (TMR) on critical work, defer non-critical compute, raise
   SDC/SEU monitoring sensitivity. Never auto-shuts-down a workload.

TERRESTRIAL RELEVANCE: storms hit high-altitude/polar sites hardest
(17-32% higher error acceleration per research); the May 2024 Gannon storm
(G5, strongest in 20 yrs) affected ground systems. This is usable on Earth
today with the live feed -- not orbital-only telemetry.

NOTE: Logic-tested against NOAA's published thresholds and format. The
feed is real; whether a specific GPU's SEU rate tracks flux as expected
needs hardware validation. Warning lead time is a window (20 min-hours),
not a guarantee.
"""

import math
from datetime import datetime, timezone

# NOAA S-scale on >=10 MeV integral proton flux (pfu). Published values.
S_SCALE = [
    (100_000.0, "S5", "extreme"),
    (10_000.0,  "S4", "severe"),
    (1_000.0,   "S3", "strong"),
    (100.0,     "S2", "moderate"),
    (10.0,      "S1", "minor"),
]
HARD_PROTON_ALERT_PFU = 1.0   # >=100 MeV alert threshold


def classify_s_level(flux_10mev_pfu: float):
    """Return (level, label) per NOAA S-scale, or ('S0','background')."""
    f = float(flux_10mev_pfu)
    for thr, level, label in S_SCALE:
        if f >= thr:
            return level, label
    return "S0", "background"


def parse_noaa_integral_protons(records: list, energy: str = ">=10 MeV") -> list:
    """Filter NOAA 'integral-protons' JSON records to one energy channel.
    Returns [(time_tag, flux)] sorted by time. Tolerates missing/None flux."""
    out = []
    for r in records or []:
        if r.get("energy") != energy:
            continue
        flux = r.get("flux")
        if flux is None:
            continue
        try:
            out.append((r.get("time_tag"), float(flux)))
        except (TypeError, ValueError):
            continue
    out.sort(key=lambda x: (x[0] or ""))
    return out


# ---------------------------------------------------------------------------
# 1 -- Solar Particle Event detector
# ---------------------------------------------------------------------------
class SolarParticleEventDetector:
    """
    Tracks >=10 MeV (S-scale) and >=100 MeV (hard-proton) flux. Detects:
      - current S-level (threshold classification, NOAA-published)
      - ONSET: flux rises by >= onset_decades orders of magnitude over the
        recent background within onset_window samples (5-min cadence ->
        default window ~1 hour). This fires at the START of a storm.
      - hard-proton alert (>=100 MeV >= 1 pfu): the penetrating population
        that most directly drives SEUs in shielded electronics.
    """

    def __init__(self, onset_decades=1.0, onset_window=12, background_window=48):
        self.onset_decades = onset_decades          # 10x rise = 1 decade
        self.onset_window = onset_window            # samples (~1h at 5-min)
        self.background_window = background_window  # samples (~4h)
        self._flux10 = []
        self._flux100 = []
        self.checks = 0
        self.flags = 0
        self._last_level = "S0"

    def update(self, flux_10mev_pfu: float, flux_100mev_pfu: float = None,
               time_tag: str = None) -> dict:
        self.checks += 1
        f10 = max(0.0, float(flux_10mev_pfu))
        self._flux10.append(f10)
        if len(self._flux10) > self.background_window + self.onset_window:
            self._flux10.pop(0)
        if flux_100mev_pfu is not None:
            self._flux100.append(max(0.0, float(flux_100mev_pfu)))
            if len(self._flux100) > self.background_window:
                self._flux100.pop(0)

        level, label = classify_s_level(f10)

        # onset: compare recent window to prior background (log10 rise)
        onset = False
        decades = None
        if len(self._flux10) > self.onset_window + 3:
            bg = self._flux10[:-self.onset_window]
            bg_med = sorted(bg)[len(bg) // 2]
            recent_max = max(self._flux10[-self.onset_window:])
            if bg_med > 0 and recent_max > 0:
                decades = math.log10(recent_max) - math.log10(bg_med)
                onset = decades >= self.onset_decades and recent_max >= 10.0  # at least S1

        hard_alert = (flux_100mev_pfu is not None and float(flux_100mev_pfu) >= HARD_PROTON_ALERT_PFU)
        escalated = self._levels_rank(level) > self._levels_rank(self._last_level)
        self._last_level = level

        result = {
            "substrate": "space_weather",
            "time_tag": time_tag or datetime.now(timezone.utc).isoformat(),
            "flux_10mev_pfu": f10,
            "flux_100mev_pfu": flux_100mev_pfu,
            "s_level": level,
            "s_label": label,
            "onset_detected": onset,
            "onset_decades": None if decades is None else round(decades, 2),
            "hard_proton_alert": hard_alert,
            "agent": "SolarParticleEventDetector",
            "cite": "NOAA SWPC GOES integral proton flux; NOAA S-scale (10/100/1k/10k/100k pfu at >=10 MeV; 1 pfu at >=100 MeV)",
        }

        if onset or (level != "S0" and escalated) or hard_alert:
            self.flags += 1
            result["type"] = "SOLAR_PARTICLE_EVENT"
            result["severity"] = ("CRITICAL" if level in ("S3", "S4", "S5") or hard_alert
                                  else "WARNING")
            result["swarm_signal"] = "SOLAR_PARTICLE_EVENT"
            result["detail"] = (f"{'ONSET ' if onset else ''}{level} ({label}); "
                                f"{'>=100 MeV hard-proton alert; ' if hard_alert else ''}"
                                "SEU rate rises with flux -- harden posture now")
        elif level != "S0":
            result["type"] = "SOLAR_STORM_ONGOING"
            result["severity"] = "WARNING"
            result["swarm_signal"] = "SOLAR_STORM_ONGOING"
        else:
            result["type"] = "SPACE_WEATHER_QUIET"
            result["severity"] = "INFO"
        return result

    @staticmethod
    def _levels_rank(level: str) -> int:
        return {"S0": 0, "S1": 1, "S2": 2, "S3": 3, "S4": 4, "S5": 5}.get(level, 0)

    def ingest_noaa(self, records: list) -> dict:
        """Convenience: feed a NOAA integral-protons JSON payload (list of
        records) and return the result for the latest sample."""
        f10 = parse_noaa_integral_protons(records, ">=10 MeV")
        f100 = parse_noaa_integral_protons(records, ">=100 MeV")
        f100_map = dict(f100)
        last = None
        for t, f in f10:
            last = self.update(f, f100_map.get(t), time_tag=t)
        return last or {"type": "SPACE_WEATHER_NO_DATA", "severity": "INFO"}

    def get_stats(self):
        return {"component": "SolarParticleEventDetector", "checks": self.checks,
                "flags": self.flags, "current_level": self._last_level}


# ---------------------------------------------------------------------------
# 2 -- Space-weather early-warning ingest
# ---------------------------------------------------------------------------
class SpaceWeatherWarningIngest:
    """
    NOAA issues Proton Event WARNINGs on the EXPECTATION of exceeding a
    threshold ("Warning of expected ONSET", "expected PERSISTENCE"), before
    the flux is measured -- this is the head start. Also handles ALERTs
    (threshold crossed) and SUMMARYs (event ended).

    Accepts NOAA alert/warning products as dicts:
      {"product": "WARNING"|"ALERT"|"SUMMARY", "threshold_pfu": 10,
       "energy": ">=10 MeV", "issue_time": "...", "valid_from": "...",
       "valid_to": "...", "message": "..."}
    """

    def __init__(self):
        self.active_warnings = {}
        self.events = 0

    def ingest(self, product: dict) -> dict:
        self.events += 1
        kind = (product.get("product") or "").upper()
        thr = float(product.get("threshold_pfu", 0) or 0)
        energy = product.get("energy", ">=10 MeV")
        key = f"{energy}:{thr:g}"
        level, label = classify_s_level(thr) if energy == ">=10 MeV" else ("HARD", "hard-proton")

        result = {
            "substrate": "space_weather",
            "product": kind,
            "energy": energy,
            "threshold_pfu": thr,
            "expected_level": level,
            "issue_time": product.get("issue_time"),
            "valid_to": product.get("valid_to"),
            "agent": "SpaceWeatherWarningIngest",
            "cite": "NOAA SWPC Proton Event WARNING/ALERT/SUMMARY products",
        }

        if kind == "WARNING":
            self.active_warnings[key] = product
            result["type"] = "SOLAR_STORM_WARNING"
            result["severity"] = "WARNING" if level in ("S1", "S2") else "CRITICAL"
            result["swarm_signal"] = "SOLAR_STORM_WARNING"
            result["lead_time_note"] = ("early-warning window: protons arrive 20 min to "
                                        "many hours after the flare -- harden NOW")
        elif kind == "ALERT":
            self.active_warnings[key] = product
            result["type"] = "SOLAR_STORM_ALERT"
            result["severity"] = "CRITICAL" if level in ("S3", "S4", "S5", "HARD") else "WARNING"
            result["swarm_signal"] = "SOLAR_STORM_ALERT"
        elif kind == "SUMMARY":
            self.active_warnings.pop(key, None)
            result["type"] = "SOLAR_STORM_ENDED"
            result["severity"] = "INFO"
        else:
            result["type"] = "SPACE_WEATHER_PRODUCT_UNKNOWN"
            result["severity"] = "INFO"
        result["active_warnings"] = len(self.active_warnings)
        return result

    def get_stats(self):
        return {"component": "SpaceWeatherWarningIngest", "events": self.events,
                "active_warnings": len(self.active_warnings)}


# ---------------------------------------------------------------------------
# 3 -- Storm-hardening posture controller (gated)
# ---------------------------------------------------------------------------
# Posture per S-level. Everything here is a RECOMMENDATION; nothing auto-executes.
POSTURE = {
    "S0": {"posture": "NORMAL", "actions": []},
    "S1": {"posture": "ELEVATED_MONITORING",
           "actions": ["raise_sdc_seu_monitor_sensitivity", "log_storm_correlated_errors"]},
    "S2": {"posture": "CHECKPOINT",
           "actions": ["raise_sdc_seu_monitor_sensitivity", "checkpoint_critical_state",
                       "log_storm_correlated_errors"]},
    "S3": {"posture": "HARDENED",
           "actions": ["checkpoint_critical_state", "enable_tmr_on_critical_workloads",
                       "defer_non_critical_compute", "raise_sdc_seu_monitor_sensitivity"]},
    "S4": {"posture": "DEFENSIVE",
           "actions": ["checkpoint_critical_state", "enable_tmr_on_critical_workloads",
                       "defer_non_critical_compute", "pause_sensitive_workloads_gated",
                       "raise_sdc_seu_monitor_sensitivity"]},
    "S5": {"posture": "SURVIVAL",
           "actions": ["checkpoint_critical_state", "pause_sensitive_workloads_gated",
                       "safe_hold_non_essential_hardware_gated", "enable_tmr_on_critical_workloads",
                       "raise_sdc_seu_monitor_sensitivity"]},
}
GATED_ACTIONS = {"pause_sensitive_workloads_gated", "safe_hold_non_essential_hardware_gated",
                 "defer_non_critical_compute"}


class StormHardeningPosture:
    """Maps a detected/forecast S-level to a recommended posture. Actions that
    disrupt running work are GATED (human approves); monitoring/checkpoint/
    verification actions are auto-safe."""

    def __init__(self):
        self.current = "S0"
        self.changes = 0

    def recommend(self, s_level: str, source: str = "measured") -> dict:
        spec = POSTURE.get(s_level, POSTURE["S0"])
        changed = s_level != self.current
        if changed:
            self.changes += 1
        self.current = s_level
        actions = [{"action": a,
                    "mode": "gated_approval_request" if a in GATED_ACTIONS else "auto_safe"}
                   for a in spec["actions"]]
        return {
            "type": "STORM_POSTURE_RECOMMENDATION",
            "s_level": s_level,
            "posture": spec["posture"],
            "source": source,   # 'measured' (flux) or 'forecast' (NOAA warning)
            "posture_changed": changed,
            "actions": actions,
            "severity": {"S0": "INFO", "S1": "INFO", "S2": "WARNING", "S3": "WARNING",
                         "S4": "CRITICAL", "S5": "CRITICAL"}.get(s_level, "INFO"),
            "agent": "StormHardeningPosture",
            "gating_note": ("checkpoint/verification/monitoring actions are auto-safe; "
                            "anything that pauses or holds running work is gated -- "
                            "never auto-shuts-down a workload"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_stats(self):
        return {"component": "StormHardeningPosture", "current_level": self.current,
                "posture_changes": self.changes}


if __name__ == "__main__":
    # Simulate the 28 Oct 2003 onset: ~2 pfu background -> >5,000 pfu
    det = SolarParticleEventDetector()
    for _ in range(50):
        det.update(2.0)
    r = None
    for f in (5, 30, 200, 900, 2500, 5200, 8000, 12000):
        r = det.update(f, flux_100mev_pfu=f / 100.0)
        if r["type"] == "SOLAR_PARTICLE_EVENT":
            break
    print("[SPE]", r["type"], r["s_level"], "onset:", r["onset_detected"], "decades:", r["onset_decades"])

    w = SpaceWeatherWarningIngest()
    print("[WARN]", w.ingest({"product": "WARNING", "threshold_pfu": 100, "energy": ">=10 MeV"})["type"])

    p = StormHardeningPosture()
    rec = p.recommend("S4", source="forecast")
    print("[POSTURE]", rec["posture"], [a["action"] for a in rec["actions"]])
