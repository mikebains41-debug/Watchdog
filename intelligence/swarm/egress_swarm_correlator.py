#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
egress_swarm_correlator.py -- Egress + Escape Swarm Correlation

Completes the ROME incident. The agent-sandbox-escape detector catches the
GPU half (escape -> GPU grab -> mining). This correlator fuses that with the
NETWORK half (reverse tunnel / hidden egress) that the egress detector
catches -- producing the FULL incident that neither a sandbox provider
(no GPU visibility) nor a network tool (no GPU visibility) can assemble
alone.

Rules:
- FULL_ROME_INCIDENT: sandbox escape (GPU) + reverse tunnel/egress (network)
  in one window = the complete escape-and-exfiltrate story.
- EXFILTRATION_SUSPECTED: an egress beacon co-occurring with a model-
  extraction or covert-compute signal = data/model being shipped out.

Feeds the unified correlator.

NOTE: Simulation-based. Requires real hardware validation.
"""
import collections
import time
from datetime import datetime, timezone


EGRESS_CORRELATION_RULES = [
    {
        "name": "FULL_ROME_INCIDENT",
        "required": {"AGENT_SANDBOX_ESCAPE"},
        "any_of": {"REVERSE_TUNNEL", "UNEXPECTED_EGRESS"},
        "severity": "CRITICAL",
        "story": ("Complete escape-and-exfiltrate: an agent broke its sandbox "
                  "and grabbed GPU resources AND opened an outbound tunnel / "
                  "unexpected egress. The full ROME incident -- GPU half + "
                  "network half fused. No sandbox provider or network tool sees "
                  "both. Isolate the agent, block the egress endpoint, preserve "
                  "forensics."),
    },
    {
        "name": "EXFILTRATION_SUSPECTED",
        "required": {"EGRESS_BEACON"},
        "any_of": {"MODEL_EXTRACTION_PRECURSOR_PREDICTED",
                   "COVERT_COMPUTE_ONSET_PREDICTED", "AGENT_SANDBOX_ESCAPE"},
        "severity": "CRITICAL",
        "story": ("A regular-interval outbound beacon co-occurring with a "
                  "model-extraction / covert-compute / escape signal -- "
                  "consistent with model or data exfiltration in progress."),
    },
]


class EgressSwarmCorrelator:
    def __init__(self, window_seconds=60.0, time_fn=time.time):
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
        for rule in EGRESS_CORRELATION_RULES:
            if not (rule["required"].issubset(present) and (rule["any_of"] & present)):
                continue
            key = rule["name"]
            if key in self._fired:
                continue
            contributing = [a for (_, t, a) in self._recent
                            if t in rule["required"] or t in rule["any_of"]]
            self._fired.append(key)
            self.incident_count += 1
            inc = {
                "type": "EGRESS_CORRELATED_INCIDENT",
                "incident": rule["name"],
                "severity": rule["severity"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "triggering_types": sorted(rule["required"] | rule["any_of"]),
                "contributing_alerts": contributing,
                "story": rule["story"],
                "agent": "EgressSwarmCorrelator",
                "differentiator_note": (
                    "Fuses the GPU-layer escape signal with the network-egress "
                    "signal -- a complete incident neither a sandbox provider nor "
                    "a network tool can assemble, because each sees only half."),
                "recommended_action": {
                    "action": "isolate_agent_block_egress_preserve", "risk": "gated"},
                "note": "Simulation-based; correlation not proof of breach.",
            }
            print(f"[EGRESS-CORRELATOR] {rule['name']} ({rule['severity']})")
            incidents.append(inc)
        return incidents

    def get_stats(self):
        return {"component": "EgressSwarmCorrelator",
                "window_seconds": self.window_seconds,
                "alerts_in_window": len(self._recent),
                "incidents_fired": self.incident_count,
                "rules": [r["name"] for r in EGRESS_CORRELATION_RULES]}


if __name__ == "__main__":
    clock = {"t": 1000.0}
    c = EgressSwarmCorrelator(time_fn=lambda: clock["t"])
    print("escape alone:", [i["incident"] for i in
          c.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"})])
    clock["t"] += 3
    print("+ reverse tunnel -> FULL ROME:", [i["incident"] for i in
          c.observe({"swarm_signal": "REVERSE_TUNNEL"})])
    print("stats:", c.get_stats())
