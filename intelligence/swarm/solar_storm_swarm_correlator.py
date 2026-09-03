#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
solar_storm_swarm_correlator.py -- Space-Weather Swarm Correlation

Ties the CAUSE (a solar particle event, from NOAA) to the EFFECT
(corruption / latch-up / ECC events, from Watchdog's own detectors). This
is the physics-to-integrity fusion: without it, a burst of SDC during a
storm looks like random hardware trouble; with it, it is a storm-induced
event with a known cause, a known duration, and a known posture.

Rules:
- STORM_INDUCED_DEGRADATION: SPE (measured or alerted) + rising SDC /
  ECC / SEL -> the storm is corrupting compute. Hold the hardened posture;
  results from the window are suspect.
- STORM_LATCHUP_EVENT: SPE + SEL latch-up -> a heavy-ion strike from the
  storm latched a part; power-cycle (gated) before burn-out.
- PRE_STORM_HARDENING_MISSED: a storm ALERT (flux already crossed) with
  NO prior WARNING ingested -> the early-warning window was not used;
  operational finding (improve the warning feed), not a hardware fault.

NOTE: Simulation-based. Requires real hardware validation.
"""
import collections
import time
from datetime import datetime, timezone


STORM_RULES = [
    {
        "name": "STORM_INDUCED_DEGRADATION",
        "required_any": {"SOLAR_PARTICLE_EVENT", "SOLAR_STORM_ALERT", "SOLAR_STORM_ONGOING"},
        "any_of": {"SDC_CORRUPTION_DETECTED", "ECC_BREAK_SUSPECTED",
                   "GPUTHOR_PRECURSOR_PREDICTED", "TID_THRESHOLD_CROSSED"},
        "severity": "CRITICAL",
        "story": ("A solar particle event is co-occurring with compute corruption / "
                  "ECC events: the storm is driving the SEU rate. Hold the hardened "
                  "posture; treat results computed in the storm window as suspect "
                  "until re-verified."),
    },
    {
        "name": "STORM_LATCHUP_EVENT",
        "required_any": {"SOLAR_PARTICLE_EVENT", "SOLAR_STORM_ALERT", "SOLAR_STORM_ONGOING"},
        "any_of": {"SEL_LATCHUP_SUSPECTED"},
        "severity": "CRITICAL",
        "story": ("A latch-up during a solar particle event: a storm heavy-ion strike "
                  "latched a part. Power-cycle (gated) before thermal burn-out."),
    },
]


class SolarStormSwarmCorrelator:
    def __init__(self, window_seconds=6 * 3600.0, time_fn=time.time):
        # storms last hours; a wide window is correct here
        self.window_seconds = window_seconds
        self._time_fn = time_fn
        self._recent = collections.deque()
        self._fired = collections.deque(maxlen=200)
        self._saw_warning = False
        self.incident_count = 0

    def _prune(self, now):
        cutoff = now - self.window_seconds
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

    def observe(self, alert: dict) -> list:
        now = self._time_fn()
        atype = alert.get("swarm_signal") or alert.get("type")
        if not atype:
            return []
        if atype == "SOLAR_STORM_WARNING":
            self._saw_warning = True
        if atype == "SOLAR_STORM_ENDED":
            self._saw_warning = False
        self._recent.append((now, atype, alert))
        self._prune(now)
        incidents = self._evaluate()

        # operational finding: an ALERT with no prior WARNING = window missed
        if atype == "SOLAR_STORM_ALERT" and not self._saw_warning \
                and "PRE_STORM_HARDENING_MISSED" not in self._fired:
            self._fired.append("PRE_STORM_HARDENING_MISSED")
            self.incident_count += 1
            incidents.append({
                "type": "SPACE_WEATHER_INCIDENT",
                "incident": "PRE_STORM_HARDENING_MISSED",
                "severity": "WARNING",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "story": ("A storm ALERT arrived with no prior WARNING ingested -- the "
                          "early-warning window was not used. Operational finding: "
                          "check the NOAA warning feed, not a hardware fault."),
                "agent": "SolarStormSwarmCorrelator",
                "recommended_action": {"action": "verify_space_weather_warning_feed",
                                       "risk": "advisory"},
            })
        return incidents

    def _evaluate(self) -> list:
        present = {t for (_, t, _) in self._recent}
        incidents = []
        for rule in STORM_RULES:
            if not (rule["required_any"] & present) or not (rule["any_of"] & present):
                continue
            if rule["name"] in self._fired:
                continue
            contributing = [a for (_, t, a) in self._recent
                            if t in rule["required_any"] or t in rule["any_of"]]
            self._fired.append(rule["name"])
            self.incident_count += 1
            incidents.append({
                "type": "SPACE_WEATHER_INCIDENT",
                "incident": rule["name"],
                "severity": rule["severity"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "triggering_types": sorted(rule["required_any"] | rule["any_of"]),
                "contributing_alerts": contributing,
                "story": rule["story"],
                "agent": "SolarStormSwarmCorrelator",
                "differentiator_note": ("ties the storm (cause, NOAA feed) to the "
                                        "corruption (effect, Watchdog detectors)"),
                "recommended_action": {"action": "hold_hardened_posture_reverify_results",
                                       "risk": "gated"},
                "note": "Simulation-based; correlation not proof.",
            })
            print(f"[STORM-CORRELATOR] {rule['name']} ({rule['severity']})")
        return incidents

    def get_stats(self):
        return {"component": "SolarStormSwarmCorrelator",
                "window_seconds": self.window_seconds,
                "alerts_in_window": len(self._recent),
                "incidents_fired": self.incident_count,
                "warning_active": self._saw_warning,
                "rules": [r["name"] for r in STORM_RULES] + ["PRE_STORM_HARDENING_MISSED"]}


if __name__ == "__main__":
    clock = {"t": 1000.0}
    c = SolarStormSwarmCorrelator(time_fn=lambda: clock["t"])
    print("storm alone:", [i["incident"] for i in c.observe({"swarm_signal": "SOLAR_PARTICLE_EVENT"})])
    clock["t"] += 600
    print("+ SDC -> storm-induced:", [i["incident"] for i in c.observe({"type": "SDC_CORRUPTION_DETECTED"})])
