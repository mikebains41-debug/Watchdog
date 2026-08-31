#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
sdc_swarm_correlator.py -- SDC Swarm Correlation

Feeds SDC compute-integrity signals into the swarm's correlation discipline.
The key rule: SDC scales with silicon age, temperature, and load (BTI/HCI
hold violations; droop-induced timing violations). So an SDC flag
co-occurring with an ECC-break precursor AND high temperature is not a
one-off -- it is a "degrading silicon" incident: the card is wearing out and
starting to miscompute under load.

This lets Watchdog tell one coherent hardware-integrity story across
memory (ECC), computation (SDC), and thermal -- correlated, not scattered.

Consumes the alerts the SDC detectors emit plus existing agent alerts, and
fires DEGRADING_SILICON_INCIDENT when the combination appears in a window.
De-duped, conservative, honest (a correlation is not proof).

NOTE: Simulation-based. Requires real hardware validation.
"""
import collections
import time
from datetime import datetime, timezone


SDC_CORRELATION_RULES = [
    {
        "name": "DEGRADING_SILICON_INCIDENT",
        "required": {"SDC_CORRUPTION_DETECTED"},
        "any_of": {"GPUTHOR_PRECURSOR_PREDICTED", "ECC_BREAK_SUSPECTED",
                   "THERMAL_EVENT_PREDICTED"},
        "severity": "CRITICAL",
        "story": ("Compute-integrity corruption co-occurring with an ECC/thermal "
                  "signal: consistent with silicon aging/degradation (BTI/HCI "
                  "hold violations) causing the card to miscompute under load. "
                  "Not a transient -- schedule the GPU out."),
    },
    {
        "name": "DROOP_INDUCED_CORRUPTION_CONFIRMED",
        "required": {"DROOP_INDUCED_SDC_CONFIRMED"},
        "any_of": set(),   # already a fused signal on its own
        "severity": "CRITICAL",
        "story": ("Voltage/power droop physically correlated with a compute "
                  "corruption -- a dI/dt timing violation. Reduce clock or raise "
                  "voltage margin on this GPU; if GPU Optimizer is undervolting, "
                  "back off its margin here."),
    },
]


class SDCSwarmCorrelator:
    def __init__(self, window_seconds=30.0, time_fn=time.time):
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
        atype = alert.get("type")
        if not atype:
            return []
        self._recent.append((now, atype, alert))
        self._prune(now)
        return self._evaluate()

    def _evaluate(self) -> list:
        present = {t for (_, t, _) in self._recent}
        incidents = []
        for rule in SDC_CORRELATION_RULES:
            req_ok = rule["required"].issubset(present)
            any_ok = (not rule["any_of"]) or bool(rule["any_of"] & present)
            if not (req_ok and any_ok):
                continue
            key = (rule["name"], frozenset(rule["required"]))
            if key in self._fired:
                continue
            contributing = [a for (_, t, a) in self._recent
                            if t in rule["required"] or t in rule["any_of"]]
            self._fired.append(key)
            self.incident_count += 1
            inc = {
                "type": "SDC_CORRELATED_INCIDENT",
                "incident": rule["name"],
                "severity": rule["severity"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "triggering_types": sorted(rule["required"] | rule["any_of"]),
                "contributing_alerts": contributing,
                "story": rule["story"],
                "agent": "SDCSwarmCorrelator",
                "recommended_action": {
                    "action": "schedule_gpu_out_and_preserve_evidence",
                    "risk": "gated"},
                "note": "Simulation-based; correlation not proof of breach.",
            }
            print(f"[SDC-CORRELATOR] {rule['name']} ({rule['severity']})")
            incidents.append(inc)
        return incidents

    def get_stats(self):
        return {"component": "SDCSwarmCorrelator",
                "window_seconds": self.window_seconds,
                "alerts_in_window": len(self._recent),
                "incidents_fired": self.incident_count,
                "rules": [r["name"] for r in SDC_CORRELATION_RULES]}


if __name__ == "__main__":
    clock = {"t": 1000.0}
    c = SDCSwarmCorrelator(time_fn=lambda: clock["t"])
    print("sdc alone:", [i["incident"] for i in c.observe({"type": "SDC_CORRUPTION_DETECTED"})])
    clock["t"] += 3
    print("+ ecc-break:", [i["incident"] for i in c.observe({"type": "ECC_BREAK_SUSPECTED"})])
    print("stats:", c.get_stats())
