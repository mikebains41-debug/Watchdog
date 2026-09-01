#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
sandbox_swarm_correlator.py -- Agent-Sandbox-Escape Swarm Correlation

Turns individual sandbox-isolation signals into correlated incidents that
no sandbox provider can assemble. The whole point: a single "sandbox used
some GPU" signal is weak; the SWARM fusing sandbox-escape + covert-compute +
cross-sandbox residual + a security precursor into ONE incident is the
superior, differentiated detection.

This is exactly the ROME incident, told as a fused story: an agent escaped
its sandbox (ESCAPE_TO_GPU) AND grabbed GPU compute in a mining pattern
(POST_ESCAPE_COVERT_COMPUTE / COVERT_COMPUTE_ONSET_PREDICTED) AND possibly
read another sandbox's residual (CROSS_SANDBOX_VRAM_RESIDUAL). No kernel-
level tool (Firecracker/gVisor) sees any of the GPU half; Watchdog's swarm
sees and correlates all of it.

Feeds the unified correlator: emits AGENT_SANDBOX_ESCAPE_INCIDENT which the
unified layer can further fuse with the broader security picture.

NOTE: Simulation-based. Requires real hardware validation.
"""
import collections
import time
from datetime import datetime, timezone


SANDBOX_CORRELATION_RULES = [
    {
        "name": "AGENT_SANDBOX_ESCAPE_INCIDENT",
        "required": {"AGENT_SANDBOX_ESCAPE"},
        "any_of": {"COVERT_COMPUTE_ONSET_PREDICTED", "AGENT_SANDBOX_ESCAPE"},
        "severity": "CRITICAL",
        "story": ("An agent escaped its sandbox boundary and grabbed GPU "
                  "resources -- the ROME class of incident. Kernel-level "
                  "isolation (Firecracker/gVisor) does not see the GPU footprint; "
                  "Watchdog does. Isolate the sandbox and preserve forensics."),
    },
    {
        "name": "MULTI_AGENT_ISOLATION_COLLAPSE",
        "required": {"AGENT_SANDBOX_ESCAPE"},
        "any_of": {"SDC_CORRUPTION_DETECTED", "GPUTHOR_PRECURSOR_PREDICTED",
                   "TENANT_ISOLATION_RISK"},
        "severity": "CRITICAL",
        "story": ("A sandbox-escape co-occurring with a hardware-integrity or "
                  "tenant-isolation signal on the same shared GPU -- the many-"
                  "agent isolation boundary is collapsing across the compute "
                  "layer. Evacuate affected agents, quarantine the node."),
    },
]


class SandboxSwarmCorrelator:
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
        # accept either the detector's `type` or its `swarm_signal`
        atype = alert.get("swarm_signal") or alert.get("type")
        if not atype:
            return []
        self._recent.append((now, atype, alert))
        self._prune(now)
        return self._evaluate()

    def _evaluate(self) -> list:
        present = {t for (_, t, _) in self._recent}
        incidents = []
        for rule in SANDBOX_CORRELATION_RULES:
            req_ok = rule["required"].issubset(present)
            any_ok = bool(rule["any_of"] & present)
            if not (req_ok and any_ok):
                continue
            key = rule["name"]
            if key in self._fired:
                continue
            contributing = [a for (_, t, a) in self._recent
                            if t in rule["required"] or t in rule["any_of"]]
            self._fired.append(key)
            self.incident_count += 1
            inc = {
                "type": "SANDBOX_CORRELATED_INCIDENT",
                "incident": rule["name"],
                "severity": rule["severity"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "triggering_types": sorted(rule["required"] | rule["any_of"]),
                "contributing_alerts": contributing,
                "story": rule["story"],
                "agent": "SandboxSwarmCorrelator",
                "differentiator_note": (
                    "GPU-layer agent-sandbox-escape correlation -- an incident "
                    "no kernel-level sandbox provider can assemble, because they "
                    "do not watch GPU telemetry."),
                "recommended_action": {
                    "action": "isolate_sandbox_evacuate_preserve", "risk": "gated"},
                "note": "Simulation-based; correlation not proof of breach.",
            }
            print(f"[SANDBOX-CORRELATOR] {rule['name']} ({rule['severity']})")
            incidents.append(inc)
        return incidents

    def get_stats(self):
        return {"component": "SandboxSwarmCorrelator",
                "window_seconds": self.window_seconds,
                "alerts_in_window": len(self._recent),
                "incidents_fired": self.incident_count,
                "rules": [r["name"] for r in SANDBOX_CORRELATION_RULES]}


if __name__ == "__main__":
    clock = {"t": 1000.0}
    c = SandboxSwarmCorrelator(time_fn=lambda: clock["t"])
    print("escape alone:", [i["incident"] for i in
          c.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"})])
    clock["t"] += 2
    print("+ covert compute:", [i["incident"] for i in
          c.observe({"type": "COVERT_COMPUTE_ONSET_PREDICTED"})])
    print("stats:", c.get_stats())
