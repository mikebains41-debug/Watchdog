#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
cross_layer_correlator.py -- Cross-Substrate Fusion Correlation

Extends the swarm's correlation discipline to the thing no software-only
competitor can assemble: correlating a SOFTWARE-layer signal with its
PHYSICAL-layer corroborator, across GPU / CPU / quantum, into one
high-confidence incident.

A HiddenLayer or Lakera sees the text half of an injection. Watchdog's
swarm sees the text half AND the power/timing/fidelity half AND the
model-file half -- and this correlator fuses them into a single incident
that is strictly more confident than any single-layer alert.

It consumes the alerts the fusion detectors (and existing agents) emit and
fires CROSS_LAYER_INCIDENT when a defined multi-layer combination appears
within a time window. De-duped, conservative (all required alert types
must co-occur), and honest (a correlation is not proof).

NOTE: Simulation-based. Requires real hardware validation.
"""
import collections
import time
from datetime import datetime, timezone


# Rules pairing a software-layer signal with a physical corroborator (and
# sometimes a third model-file/supply-chain signal). Each escalates to a
# single incident with confidence higher than its parts.
CROSS_LAYER_RULES = [
    {
        "name": "CONFIRMED_INJECTION_CAMPAIGN",
        "required": {"PROMPT_INJECTION_PHYSICALLY_CONFIRMED"},
        "any_of": {"MODEL_TAMPER_CONFIRMED", "MODEL_TAMPER_HARDWARE_MISMATCH"},
        "severity": "CRITICAL",
        "story": ("Prompt injection confirmed by physical substrate signature, "
                  "co-occurring with model tamper -- a coordinated attack "
                  "visible only across the software + hardware layers."),
    },
    {
        "name": "STEALTH_MODEL_SWAP",
        "required": {"MODEL_TAMPER_HARDWARE_MISMATCH"},
        "any_of": {"PROMPT_PHYSICAL_ANOMALY", "GPUTHOR_PRECURSOR_PREDICTED"},
        "severity": "CRITICAL",
        "story": ("A model that scanned clean but whose runtime physical "
                  "footprint diverges, alongside another physical anomaly -- "
                  "a swap a file-scan-only tool would miss entirely."),
    },
    {
        "name": "EVASIVE_INJECTION_CAUGHT_BY_PHYSICS",
        "required": {"PROMPT_PHYSICAL_ANOMALY"},
        "any_of": {"COVERT_COMPUTE_ONSET_PREDICTED", "INFERENCE_POWER_ANOMALY"},
        "severity": "WARNING",
        "story": ("A prompt that read benign but produced an anomalous "
                  "compute signature, with a corroborating compute anomaly -- "
                  "an injection that evaded content analysis, caught by physics."),
    },
    {
        "name": "QUANTUM_JOB_TAMPER_CONFIRMED",
        "required": {"PROMPT_INJECTION_PHYSICALLY_CONFIRMED"},
        "any_of": {"THREAT_INTEL_MATCH"},
        "substrate": "quantum",
        "severity": "CRITICAL",
        "story": ("A quantum job whose parameters were flagged AND whose "
                  "circuit physics (fidelity/CHSH) confirms tampering -- job "
                  "integrity verified by the hardware's own physics."),
    },
]


class CrossLayerCorrelator:
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
        for rule in CROSS_LAYER_RULES:
            req_ok = rule["required"].issubset(present)
            any_ok = (not rule.get("any_of")) or bool(rule["any_of"] & present)
            if not (req_ok and any_ok):
                continue
            key = (rule["name"], frozenset(rule["required"]))
            if key in self._fired:
                continue
            contributing = [a for (_, t, a) in self._recent
                            if t in rule["required"] or t in rule.get("any_of", set())]
            self._fired.append(key)
            self.incident_count += 1
            inc = {
                "type": "CROSS_LAYER_INCIDENT",
                "incident": rule["name"],
                "severity": rule["severity"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "triggering_types": sorted(rule["required"] | rule.get("any_of", set())),
                "contributing_alerts": contributing,
                "story": rule["story"],
                "agent": "CrossLayerCorrelator",
                "differentiator_note": (
                    "This incident fuses a software-layer signal with a "
                    "physical-layer corroborator -- a correlation a "
                    "software-only competitor structurally cannot produce."),
                "recommended_action": {
                    "action": "evacuate_and_preserve_forensics", "risk": "gated"},
                "note": "Simulation-based. A cross-layer correlation, not proof of breach.",
            }
            if "substrate" in rule:
                inc["substrate"] = rule["substrate"]
            print(f"[CROSS-LAYER] {rule['name']} ({rule['severity']})")
            incidents.append(inc)
        return incidents

    def get_stats(self) -> dict:
        return {
            "component": "CrossLayerCorrelator",
            "window_seconds": self.window_seconds,
            "alerts_in_window": len(self._recent),
            "incidents_fired": self.incident_count,
            "rules": [r["name"] for r in CROSS_LAYER_RULES],
        }


if __name__ == "__main__":
    clock = {"t": 1000.0}
    c = CrossLayerCorrelator(time_fn=lambda: clock["t"])
    print("physical-confirmed injection alone:",
          [i["incident"] for i in c.observe(
              {"type": "PROMPT_INJECTION_PHYSICALLY_CONFIRMED"})])
    clock["t"] += 3
    print("+ model tamper -> incident:",
          [i["incident"] for i in c.observe({"type": "MODEL_TAMPER_CONFIRMED"})])
    print("stats:", c.get_stats())
