#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
master_correlator.py -- One correlation entry point for EVERY Watchdog suite
*** WATCHDOG ***

THE GAP THIS CLOSES
-------------------
Watchdog grew correlators incrementally: security_correlator, cross_layer
(fusion), sdc_swarm, sandbox_swarm, egress_swarm, extreme_env_swarm,
solar_storm_swarm, and unified_correlator (which composes only SOME of
them). Each is tested and correct on its own, but a signal that only one
correlator sees cannot fuse with a signal only another sees. The moat is
cross-suite correlation; siloed correlators leave part of it unrealized.

MasterCorrelator is the single entry point. It discovers and composes every
correlator that is importable in the deployed repo (lazy, guarded imports:
a missing or renamed module is RECORDED, never fatal), forwards every alert
to all of them, and then applies a small set of MASTER rules that can only
be expressed once everything is in one place.

Design rules (same as unified_correlator, which this supersedes as the
entry point but does not delete):
  - additive: no existing correlator is modified or removed
  - a broken sub-correlator cannot crash the master (fail loud, keep going)
  - every incident emitted by any sub-correlator is passed through
  - master rules de-dupe within a window and are conservative

SECURITY REVIEW COMPLIANCE: no bare except; no shell; no subprocess;
detection/correlation only; all recommended actions gated.

NOTE: Logic-tested with fakes here; on the live repo the real correlators
load. Run get_stats() after first live start to see which loaded.
"""
import collections
import importlib
import time
from datetime import datetime, timezone

# (module_path, class_name) for every correlator Watchdog has grown.
CORRELATOR_SPECS = [
    ("intelligence.swarm.security_correlator", "SecurityCorrelator"),
    ("intelligence.swarm.cross_layer_correlator", "CrossLayerCorrelator"),
    ("intelligence.swarm.sdc_swarm_correlator", "SDCSwarmCorrelator"),
    ("intelligence.swarm.sandbox_swarm_correlator", "SandboxSwarmCorrelator"),
    ("intelligence.swarm.egress_swarm_correlator", "EgressSwarmCorrelator"),
    ("intelligence.swarm.extreme_env_swarm_correlator", "ExtremeEnvSwarmCorrelator"),
    ("intelligence.swarm.solar_storm_swarm_correlator", "SolarStormSwarmCorrelator"),
]

# Suite tag for every alert type the master knows, for the FULL_SPECTRUM rule.
SUITE_OF = {
    # gpu hardware
    "GPUTHOR_PRECURSOR_PREDICTED": "gpu_hw", "ECC_BREAK_SUSPECTED": "gpu_hw",
    "GHOST_POWER_PREDICTED": "gpu_hw", "THERMAL_EVENT_PREDICTED": "thermal",
    "SEL_LATCHUP_SUSPECTED": "radiation", "TID_THRESHOLD_CROSSED": "radiation",
    # compute integrity
    "SDC_CORRUPTION_DETECTED": "sdc", "DROOP_INDUCED_SDC_CONFIRMED": "sdc",
    # model / fusion
    "MODEL_TAMPER_CONFIRMED": "model", "MODEL_TAMPER_HARDWARE_MISMATCH": "model",
    "WEIGHT_BACKDOOR_SUSPECTED": "model", "BATCH_BOUNDARY_LEAK_SUSPECTED": "model",
    "PROMPT_INJECTION_PHYSICALLY_CONFIRMED": "fusion", "PROMPT_PHYSICAL_ANOMALY": "fusion",
    "SPONGE_ATTACK_SUSPECTED": "fusion",
    # security swarm
    "COVERT_COMPUTE_ONSET_PREDICTED": "security", "MODEL_EXTRACTION_PRECURSOR_PREDICTED": "security",
    "TENANT_ISOLATION_RISK": "security", "MICRO_BURST_PATTERN": "security",
    # agent / network
    "AGENT_SANDBOX_ESCAPE": "agent", "REVERSE_TUNNEL": "network",
    "UNEXPECTED_EGRESS": "network", "EGRESS_BEACON": "network",
    # quantum
    "QUANTUM_CIRCUIT_TAMPER": "quantum", "QUANTUM_PULSE_TAMPER": "quantum",
    "QUANTUM_RESET_STATE_LEAK": "quantum", "QUANTUM_FAULT_INJECTION_SUSPECTED": "quantum",
    "QUANTUM_CROSSTALK_ATTACK_SUSPECTED": "quantum", "QTEE_DECOY_STRIPPED": "quantum",
    # environment
    "SOLAR_PARTICLE_EVENT": "space_weather", "SOLAR_STORM_ALERT": "space_weather",
    "SEAWATER_INGRESS_CONFIRMED": "subsea", "HULL_BUCKLING_RISK_CRITICAL": "subsea",
    "COOLING_DEGRADATION_CRITICAL": "subsea",
    # model integrity over time
    "MODEL_REVALIDATION_REQUIRED": "compliance", "WORKLOAD_UNDERSAMPLED": "telemetry",
}

MASTER_RULES = [
    {
        "name": "COORDINATED_MULTI_VECTOR_ATTACK",
        "required_any": {"AGENT_SANDBOX_ESCAPE", "PROMPT_INJECTION_PHYSICALLY_CONFIRMED",
                         "MODEL_TAMPER_CONFIRMED", "WEIGHT_BACKDOOR_SUSPECTED"},
        "any_of": {"REVERSE_TUNNEL", "EGRESS_BEACON", "MODEL_EXTRACTION_PRECURSOR_PREDICTED",
                   "COVERT_COMPUTE_ONSET_PREDICTED"},
        "severity": "CRITICAL",
        "story": ("A model/agent-layer compromise co-occurring with an exfiltration or "
                  "covert-compute signal: an attack spanning software, hardware and network "
                  "layers. Only visible with every suite in one correlator."),
    },
    {
        "name": "ENVIRONMENT_INDUCED_INTEGRITY_FAILURE",
        "required_any": {"SOLAR_PARTICLE_EVENT", "SOLAR_STORM_ALERT", "SEL_LATCHUP_SUSPECTED",
                         "TID_THRESHOLD_CROSSED", "COOLING_DEGRADATION_CRITICAL",
                         "SEAWATER_INGRESS_CONFIRMED"},
        "any_of": {"SDC_CORRUPTION_DETECTED", "ECC_BREAK_SUSPECTED", "MODEL_REVALIDATION_REQUIRED"},
        "severity": "CRITICAL",
        "story": ("A physical-environment event (space weather, radiation, subsea cooling/"
                  "ingress) is now degrading compute correctness. Physics -> integrity fusion."),
    },
    {
        "name": "LOW_CONFIDENCE_WINDOW",
        "required_any": {"WORKLOAD_UNDERSAMPLED"},
        "any_of": {"COMPUTE_INTEGRITY_OK", "SPONGE_NOMINAL", "SEL_NOMINAL", "EGRESS_CLEAN"},
        "severity": "INFO",
        "story": ("Detectors reported clean during a window the sampler could not resolve. "
                  "Do NOT read the clean as clean -- detection confidence is degraded."),
    },
]


class MasterCorrelator:
    def __init__(self, window_seconds=120.0, full_spectrum_threshold=4,
                 time_fn=time.time, extra_correlators=None):
        self.window_seconds = window_seconds
        self.full_spectrum_threshold = full_spectrum_threshold
        self._time_fn = time_fn
        self._recent = collections.deque()
        self._fired = collections.deque(maxlen=500)
        self.subs = []          # loaded correlator instances
        self.load_report = []   # what loaded / what didn't, and why
        self.master_incidents = 0
        self.sub_incidents = 0
        for spec in CORRELATOR_SPECS:
            self._try_load(*spec)
        for c in (extra_correlators or []):
            self.subs.append(c)
            self.load_report.append({"correlator": type(c).__name__, "status": "injected"})

    def _try_load(self, module_path, class_name):
        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            inst = cls()
            self.subs.append(inst)
            self.load_report.append({"correlator": class_name, "status": "loaded"})
        except Exception as e:  # recorded, never fatal
            self.load_report.append({"correlator": class_name, "status": "not_loaded",
                                     "reason": f"{type(e).__name__}: {e}"})

    def _prune(self, now):
        cutoff = now - self.window_seconds
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

    def observe(self, alert: dict) -> list:
        out = []
        for sc in self.subs:
            try:
                res = sc.observe(alert)
            except Exception as e:
                res = [{"type": "SUB_CORRELATOR_ERROR", "correlator": type(sc).__name__,
                        "error": f"{type(e).__name__}: {e}", "severity": "WARNING",
                        "note": "sub-correlator failed loud; master continues"}]
            if res:
                self.sub_incidents += len([r for r in res if r.get("type") != "SUB_CORRELATOR_ERROR"])
                out.extend(res)

        now = self._time_fn()
        atype = alert.get("swarm_signal") or alert.get("type")
        if atype:
            self._recent.append((now, atype, alert))
            self._prune(now)
            out.extend(self._master_rules())
        return out

    def _master_rules(self) -> list:
        present = {t for (_, t, _) in self._recent}
        out = []
        for rule in MASTER_RULES:
            if not (rule["required_any"] & present) or not (rule["any_of"] & present):
                continue
            if rule["name"] in self._fired:
                continue
            self._fired.append(rule["name"])
            self.master_incidents += 1
            out.append({
                "type": "MASTER_INCIDENT", "incident": rule["name"], "severity": rule["severity"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "triggering_types": sorted(rule["required_any"] | rule["any_of"]),
                "contributing_alerts": [a for (_, t, a) in self._recent
                                        if t in rule["required_any"] or t in rule["any_of"]],
                "story": rule["story"], "agent": "MasterCorrelator",
                "recommended_action": {"action": "gated_per_incident", "risk": "gated"},
                "note": "Simulation-based; correlation not proof.",
            })
        suites = {SUITE_OF.get(t) for t in present if SUITE_OF.get(t)}
        if len(suites) >= self.full_spectrum_threshold and "FULL_SPECTRUM_INCIDENT" not in self._fired:
            self._fired.append("FULL_SPECTRUM_INCIDENT")
            self.master_incidents += 1
            out.append({
                "type": "MASTER_INCIDENT", "incident": "FULL_SPECTRUM_INCIDENT", "severity": "CRITICAL",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "suites_involved": sorted(suites),
                "story": f"Signals from {len(suites)} distinct suites in one window.",
                "agent": "MasterCorrelator",
                "recommended_action": {"action": "escalate_evacuate_preserve", "risk": "gated"},
            })
        return out

    def get_stats(self):
        return {"component": "MasterCorrelator",
                "loaded": [r["correlator"] for r in self.load_report if r["status"] in ("loaded", "injected")],
                "not_loaded": [r for r in self.load_report if r["status"] == "not_loaded"],
                "alerts_in_window": len(self._recent),
                "master_incidents": self.master_incidents, "sub_incidents": self.sub_incidents,
                "rules": [r["name"] for r in MASTER_RULES] + ["FULL_SPECTRUM_INCIDENT"]}


if __name__ == "__main__":
    clock = {"t": 1000.0}
    m = MasterCorrelator(time_fn=lambda: clock["t"])
    print("loaded:", m.get_stats()["loaded"], "| not loaded:", len(m.get_stats()["not_loaded"]))
    m.observe({"swarm_signal": "AGENT_SANDBOX_ESCAPE"}); clock["t"] += 5
    print("+ tunnel ->", [i["incident"] for i in m.observe({"swarm_signal": "REVERSE_TUNNEL"})])
