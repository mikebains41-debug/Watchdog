#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
extreme_env_swarm_correlator.py -- Extreme-Environment Swarm Correlation

Fuses the radiation-damage layer (orbit) and the subsea integrity layer
into incidents, and -- the point of the swarm -- correlates them with the
existing terrestrial signals (SDC, ECC, thermal) so a physical-environment
event is tied to its compute consequence.

Rules:
- RADIATION_DEGRADED_NODE: SEL latch-up OR a TID threshold, co-occurring
  with rising compute corruption (SDC) or ECC events -> the radiation
  environment is now damaging the compute. Retire/derate before it fails.
- LATCHUP_DESTRUCTIVE_RISK: SEL suspected + a thermal signal -> the
  latch-up current is heating the part; this is the burn-out path.
- SUBSEA_VESSEL_COMPROMISE: ingress confirmed OR hull margin critical,
  with a cooling or thermal signal -> the sealed environment is failing on
  more than one axis; retrieval-grade incident.
- COOLING_DRIVEN_INTEGRITY_LOSS: cooling degradation + SDC/thermal ->
  fouling has pushed silicon into the temperature band where SDC rises
  (the same heat->corruption physics Watchdog established terrestrially).

NOTE: Simulation-based. Requires real hardware validation.
"""
import collections
import time
from datetime import datetime, timezone


EXTREME_ENV_RULES = [
    {
        "name": "RADIATION_DEGRADED_NODE",
        "required_any": {"SEL_LATCHUP_SUSPECTED", "TID_THRESHOLD_CROSSED", "TID_RATING_EXCEEDED"},
        "any_of": {"SDC_CORRUPTION_DETECTED", "ECC_BREAK_SUSPECTED", "GPUTHOR_PRECURSOR_PREDICTED"},
        "severity": "CRITICAL",
        "story": ("A radiation-damage signal co-occurring with compute corruption / "
                  "ECC events: the radiation environment is now degrading the "
                  "compute. Retire or derate the part before it fails outright."),
    },
    {
        "name": "LATCHUP_DESTRUCTIVE_RISK",
        "required_any": {"SEL_LATCHUP_SUSPECTED"},
        "any_of": {"THERMAL_EVENT_PREDICTED", "COOLING_DEGRADATION_CRITICAL"},
        "severity": "CRITICAL",
        "story": ("Latch-up current plus a thermal signal: the parasitic current is "
                  "heating the part -- this is the burn-out path. Power-cycle "
                  "(gated) before permanent damage."),
    },
    {
        "name": "SUBSEA_VESSEL_COMPROMISE",
        "required_any": {"SEAWATER_INGRESS_CONFIRMED", "HULL_BUCKLING_RISK_CRITICAL"},
        "any_of": {"COOLING_DEGRADATION_WARNING", "COOLING_DEGRADATION_CRITICAL",
                   "THERMAL_EVENT_PREDICTED", "SEAWATER_INGRESS_SUSPECTED"},
        "severity": "CRITICAL",
        "story": ("The sealed vessel is failing on more than one physical axis "
                  "(ingress/pressure plus cooling/thermal). Retrieval-grade "
                  "incident; isolate power paths and plan recovery."),
    },
    {
        "name": "COOLING_DRIVEN_INTEGRITY_LOSS",
        "required_any": {"COOLING_DEGRADATION_WARNING", "COOLING_DEGRADATION_CRITICAL"},
        "any_of": {"SDC_CORRUPTION_DETECTED", "THERMAL_EVENT_PREDICTED"},
        "severity": "WARNING",
        "story": ("Cooling degradation (fouling) has pushed silicon into the "
                  "temperature band where silent data corruption rises -- the same "
                  "heat->corruption physics established terrestrially. Throttle and "
                  "clean before results become untrustworthy."),
    },
]


class ExtremeEnvSwarmCorrelator:
    def __init__(self, window_seconds=120.0, time_fn=time.time):
        self.window_seconds = window_seconds
        self._time_fn = time_fn
        self._recent = collections.deque()
        self._fired = collections.deque(maxlen=200)
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
        self._recent.append((now, atype, alert))
        self._prune(now)
        return self._evaluate()

    def _evaluate(self) -> list:
        present = {t for (_, t, _) in self._recent}
        incidents = []
        for rule in EXTREME_ENV_RULES:
            if not (rule["required_any"] & present) or not (rule["any_of"] & present):
                continue
            if rule["name"] in self._fired:
                continue
            contributing = [a for (_, t, a) in self._recent
                            if t in rule["required_any"] or t in rule["any_of"]]
            self._fired.append(rule["name"])
            self.incident_count += 1
            inc = {
                "type": "EXTREME_ENV_INCIDENT",
                "incident": rule["name"],
                "severity": rule["severity"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "triggering_types": sorted(rule["required_any"] | rule["any_of"]),
                "contributing_alerts": contributing,
                "story": rule["story"],
                "agent": "ExtremeEnvSwarmCorrelator",
                "differentiator_note": ("ties a physical-environment event (radiation, "
                                        "pressure, ingress, fouling) to its compute "
                                        "consequence -- the physics-to-integrity fusion"),
                "recommended_action": {"action": "gated_per_incident", "risk": "gated"},
                "note": "Simulation-based; correlation not proof of breach.",
            }
            print(f"[EXTREME-ENV] {rule['name']} ({rule['severity']})")
            incidents.append(inc)
        return incidents

    def get_stats(self):
        return {"component": "ExtremeEnvSwarmCorrelator",
                "window_seconds": self.window_seconds,
                "alerts_in_window": len(self._recent),
                "incidents_fired": self.incident_count,
                "rules": [r["name"] for r in EXTREME_ENV_RULES]}


if __name__ == "__main__":
    clock = {"t": 1000.0}
    c = ExtremeEnvSwarmCorrelator(time_fn=lambda: clock["t"])
    print("SEL alone:", [i["incident"] for i in c.observe({"swarm_signal": "SEL_LATCHUP_SUSPECTED"})])
    clock["t"] += 5
    print("+ SDC -> radiation-degraded:", [i["incident"] for i in c.observe({"type": "SDC_CORRUPTION_DETECTED"})])
    print("stats:", c.get_stats())
