#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
unified_correlator.py -- The Unified Swarm Correlation Layer

ONE brain that sees EVERY suite's signals -- GPU hardware, CPU, quantum
control-plane, cross-layer fusion, security swarm, and SDC/compute-integrity
-- and fuses across all of them. This is the moat: no software-only
competitor can correlate a compute-integrity signal against a Rowhammer
precursor against a quantum fault against a thermal event, because they
can't even see most of those layers.

DESIGN (additive, non-destructive)
----------------------------------
This layer does NOT replace the existing correlators. It COMPOSES them:
every alert fed to unified.observe() is forwarded to each registered
sub-correlator (SecurityCorrelator, CrossLayerCorrelator,
SDCSwarmCorrelator), so all their existing rules keep firing exactly as
before. On top of that, the unified layer adds NEW cross-suite rules that
only become possible when everything is in one place -- combinations that
span suites the individual correlators never saw together.

So nothing that already works breaks; the unified layer only ADDS
cross-suite incidents.

Sub-correlators are injected (dependency injection) so this module has no
hard import dependency and is fully testable with fakes. In the live repo
the caller passes the real SecurityCorrelator, CrossLayerCorrelator, and
SDCSwarmCorrelator instances.

NEW CROSS-SUITE RULES (span multiple suites)
--------------------------------------------
- CATASTROPHIC_NODE_DEGRADATION: SDC + ECC/Rowhammer precursor + thermal
  -> the node is failing across memory, compute, and temperature at once.
- COMPUTE_UNDER_ATTACK: SDC corruption + a security precursor (covert
  compute / model-extraction) -> corruption co-occurring with adversarial
  activity, not just aging.
- QUANTUM_CLASSICAL_COORDINATED: a quantum control-plane tamper + an SDC or
  security signal on the classical host -> attack spanning the QPU's
  classical control plane and its host.
- FULL_STACK_INCIDENT: signals from 3+ distinct suites in one window ->
  escalate to the highest priority regardless of specific combination.

NOTE: Simulation-based. Requires real hardware validation. Cross-suite
rules are hypotheses about co-occurring signatures, not validated against
real incident data.
"""
import collections
import time
from datetime import datetime, timezone


# Map alert types to the suite they belong to, so FULL_STACK_INCIDENT can
# count DISTINCT suites in a window.
ALERT_SUITE = {
    # SDC / compute-integrity
    "SDC_CORRUPTION_DETECTED": "sdc",
    "DROOP_INDUCED_SDC_CONFIRMED": "sdc",
    # GPU hardware / security swarm
    "GPUTHOR_PRECURSOR_PREDICTED": "gpu_hw",
    "ECC_BREAK_SUSPECTED": "gpu_hw",
    "GHOST_POWER_PREDICTED": "gpu_hw",
    "THERMAL_EVENT_PREDICTED": "thermal",
    "COVERT_COMPUTE_ONSET_PREDICTED": "security",
    "MODEL_EXTRACTION_PRECURSOR_PREDICTED": "security",
    "TENANT_ISOLATION_RISK": "security",
    "MICRO_BURST_PATTERN": "security",
    # model-file / fusion
    "MODEL_TAMPER_CONFIRMED": "model",
    "MODEL_TAMPER_HARDWARE_MISMATCH": "model",
    "PROMPT_INJECTION_PHYSICALLY_CONFIRMED": "fusion",
    "PROMPT_PHYSICAL_ANOMALY": "fusion",
    # quantum control-plane
    "QUANTUM_CIRCUIT_TAMPER": "quantum",
    "QUANTUM_PULSE_TAMPER": "quantum",
    "QUANTUM_RESET_STATE_LEAK": "quantum",
    "QUANTUM_FAULT_INJECTION_SUSPECTED": "quantum",
    "QUANTUM_CROSSTALK_ATTACK_SUSPECTED": "quantum",
    "QTEE_DECOY_STRIPPED": "quantum",
}


CROSS_SUITE_RULES = [
    {
        "name": "CATASTROPHIC_NODE_DEGRADATION",
        "required": {"SDC_CORRUPTION_DETECTED"},
        "any_of_all": [  # ALL of these groups must each have a member present
            {"GPUTHOR_PRECURSOR_PREDICTED", "ECC_BREAK_SUSPECTED"},
            {"THERMAL_EVENT_PREDICTED"},
        ],
        "severity": "CRITICAL",
        "story": ("Compute corruption + memory/ECC degradation + thermal event "
                  "in one window: the node is failing across compute, memory, and "
                  "temperature simultaneously. Evacuate and retire the GPU."),
    },
    {
        "name": "COMPUTE_UNDER_ATTACK",
        "required": {"SDC_CORRUPTION_DETECTED"},
        "any_of": {"COVERT_COMPUTE_ONSET_PREDICTED",
                   "MODEL_EXTRACTION_PRECURSOR_PREDICTED",
                   "MICRO_BURST_PATTERN"},
        "severity": "CRITICAL",
        "story": ("Compute corruption co-occurring with adversarial activity "
                  "(covert compute / extraction / hidden burst): corruption may "
                  "be attacker-induced, not just aging."),
    },
    {
        "name": "QUANTUM_CLASSICAL_COORDINATED",
        "required_any": {"QUANTUM_CIRCUIT_TAMPER", "QUANTUM_FAULT_INJECTION_SUSPECTED",
                         "QUANTUM_PULSE_TAMPER", "QTEE_DECOY_STRIPPED"},
        "any_of": {"SDC_CORRUPTION_DETECTED", "COVERT_COMPUTE_ONSET_PREDICTED",
                   "MODEL_TAMPER_CONFIRMED"},
        "severity": "CRITICAL",
        "story": ("Quantum control-plane tamper co-occurring with a classical-host "
                  "compute/security signal: an attack spanning the QPU's classical "
                  "control plane and its host."),
    },
]


class UnifiedCorrelator:
    """
    Composes sub-correlators + adds cross-suite rules. observe(alert) returns
    everything: sub-correlator incidents PLUS unified cross-suite incidents.
    """

    def __init__(self, sub_correlators=None, window_seconds=30.0,
                 full_stack_suite_threshold=3, time_fn=time.time):
        # sub_correlators: list of objects with an .observe(alert)->list method
        self.sub_correlators = sub_correlators or []
        self.window_seconds = window_seconds
        self.full_stack_suite_threshold = full_stack_suite_threshold
        self._time_fn = time_fn
        self._recent = collections.deque()
        self._fired = collections.deque(maxlen=400)
        self.unified_incident_count = 0
        self.sub_incident_count = 0

    def _prune(self, now):
        cutoff = now - self.window_seconds
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

    def observe(self, alert: dict) -> list:
        """Feed one alert. Returns sub-correlator incidents + unified
        cross-suite incidents."""
        results = []
        # 1. forward to every sub-correlator (their rules keep working)
        for sc in self.sub_correlators:
            try:
                sub = sc.observe(alert)
            except Exception:
                sub = []
            if sub:
                self.sub_incident_count += len(sub)
                results.extend(sub)

        # 2. record for unified cross-suite evaluation
        now = self._time_fn()
        atype = alert.get("type")
        if atype:
            self._recent.append((now, atype, alert))
            self._prune(now)
            results.extend(self._evaluate_cross_suite())

        return results

    def _evaluate_cross_suite(self) -> list:
        present = {t for (_, t, _) in self._recent}
        incidents = []

        for rule in CROSS_SUITE_RULES:
            if not self._rule_matches(rule, present):
                continue
            key = rule["name"]
            if key in self._fired:
                continue
            self._fired.append(key)
            self.unified_incident_count += 1
            incidents.append(self._make_incident(rule))

        # FULL_STACK_INCIDENT: 3+ distinct suites present in window
        suites_present = {ALERT_SUITE.get(t) for t in present if ALERT_SUITE.get(t)}
        if len(suites_present) >= self.full_stack_suite_threshold:
            if "FULL_STACK_INCIDENT" not in self._fired:
                self._fired.append("FULL_STACK_INCIDENT")
                self.unified_incident_count += 1
                incidents.append({
                    "type": "UNIFIED_CROSS_SUITE_INCIDENT",
                    "incident": "FULL_STACK_INCIDENT",
                    "severity": "CRITICAL",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "suites_involved": sorted(suites_present),
                    "story": (f"Signals from {len(suites_present)} distinct "
                              "detector suites within one window -- a broad, "
                              "multi-layer event no single-suite tool could assemble."),
                    "agent": "UnifiedCorrelator",
                    "differentiator_note": ("cross-suite fusion across GPU/CPU/"
                                            "quantum/SDC/model layers -- the moat"),
                    "recommended_action": {"action": "escalate_evacuate_preserve",
                                           "risk": "gated"},
                    "note": "Simulation-based; correlation not proof of breach.",
                })
        return incidents

    def _rule_matches(self, rule, present) -> bool:
        # required: all must be present
        if "required" in rule and not rule["required"].issubset(present):
            return False
        # required_any: at least one of a set must be present
        if "required_any" in rule and not (rule["required_any"] & present):
            return False
        # any_of: at least one present
        if "any_of" in rule and not (rule["any_of"] & present):
            return False
        # any_of_all: each group must have at least one member present
        if "any_of_all" in rule:
            for group in rule["any_of_all"]:
                if not (group & present):
                    return False
        return True

    def _make_incident(self, rule) -> dict:
        contributing_types = set()
        for k in ("required", "required_any", "any_of"):
            if k in rule:
                contributing_types |= rule[k]
        if "any_of_all" in rule:
            for g in rule["any_of_all"]:
                contributing_types |= g
        contributing = [a for (_, t, a) in self._recent if t in contributing_types]
        print(f"[UNIFIED] {rule['name']} ({rule['severity']})")
        return {
            "type": "UNIFIED_CROSS_SUITE_INCIDENT",
            "incident": rule["name"],
            "severity": rule["severity"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "triggering_types": sorted(contributing_types),
            "contributing_alerts": contributing,
            "story": rule["story"],
            "agent": "UnifiedCorrelator",
            "differentiator_note": ("cross-suite fusion -- a correlation a "
                                    "single-suite competitor cannot produce"),
            "recommended_action": {"action": "escalate_evacuate_preserve",
                                   "risk": "gated"},
            "note": "Simulation-based; correlation not proof of breach.",
        }

    def get_stats(self) -> dict:
        return {
            "component": "UnifiedCorrelator",
            "sub_correlators": len(self.sub_correlators),
            "window_seconds": self.window_seconds,
            "alerts_in_window": len(self._recent),
            "unified_incidents": self.unified_incident_count,
            "sub_incidents": self.sub_incident_count,
            "cross_suite_rules": [r["name"] for r in CROSS_SUITE_RULES] + ["FULL_STACK_INCIDENT"],
        }


if __name__ == "__main__":
    # Demo with a fake sub-correlator to show composition + cross-suite rules.
    class _FakeSub:
        def __init__(self): self.seen = []
        def observe(self, alert):
            self.seen.append(alert.get("type"))
            return []
    clock = {"t": 1000.0}
    sub = _FakeSub()
    u = UnifiedCorrelator(sub_correlators=[sub], time_fn=lambda: clock["t"])

    print("SDC alone:", [i["incident"] for i in u.observe({"type": "SDC_CORRUPTION_DETECTED"})])
    clock["t"] += 2
    print("+ ECC-break:", [i["incident"] for i in u.observe({"type": "ECC_BREAK_SUSPECTED"})])
    clock["t"] += 2
    print("+ thermal -> catastrophic + full-stack:",
          [i["incident"] for i in u.observe({"type": "THERMAL_EVENT_PREDICTED"})])
    print("sub saw:", sub.seen)
    print("stats:", u.get_stats())
