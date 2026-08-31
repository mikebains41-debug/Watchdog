#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog Swarm Intelligence — Security Correlation Layer

Turns a stream of individual agent alerts into correlated INCIDENTS.

The swarm's agents each fire independently. A single WARNING is often
noise; several specific WARNINGs co-occurring in a short window can tell a
coherent attack story that no single agent sees. This layer collects
alerts within a sliding time window and matches them against named
correlation rules, escalating a matched combination into one incident
with a severity higher than any of its parts.

Design goals (matching the repo's existing discipline):
- Additive: does NOT change how agents fire. It reads their output.
- Conservative: a rule only fires when its REQUIRED alert types co-occur
  within the window; partial matches do not escalate.
- Honest: an incident is a CORRELATION, not proof. Each incident states
  which alerts triggered it and that it is a correlation, not a confirmed
  breach.
- No auto-destructive action. Incidents carry a recommended_action; the
  gated/auto rules live in the existing remediation engine.

NOTE: Simulation-based. Requires real hardware validation. Correlation
rules are hypotheses about how attack signatures co-occur, not
empirically tuned against real incident data.
"""
import collections
import time
from datetime import datetime, timezone


# Each rule: required alert types that must ALL appear within the window,
# an incident name, an escalated severity, and a plain-language story.
CORRELATION_RULES = [
    {
        'name': 'COORDINATED_WEIGHT_TAMPER',
        'required': {'GPUTHOR_PRECURSOR_PREDICTED', 'MICRO_BURST_PATTERN'},
        'severity': 'CRITICAL',
        'story': ('ECC-break precursor co-occurring with hidden micro-burst '
                  'compute: consistent with an attacker hammering memory to '
                  'flip weights while masking the activity from coarse '
                  'utilization monitoring.'),
    },
    {
        'name': 'STEALTHY_RESOURCE_THEFT',
        'required': {'COVERT_COMPUTE_ONSET_PREDICTED', 'GHOST_POWER_PREDICTED'},
        'severity': 'CRITICAL',
        'story': ('Covert-compute onset co-occurring with ghost-power '
                  'prediction: consistent with unauthorized compute being '
                  'run while power/billing signals are being masked.'),
    },
    {
        'name': 'IP_EXFILTRATION_CAMPAIGN',
        'required': {'MODEL_EXTRACTION_PRECURSOR_PREDICTED',
                     'TENANT_ISOLATION_RISK'},
        'severity': 'CRITICAL',
        'story': ('Model-extraction precursor co-occurring with degraded '
                  'tenant isolation: consistent with an active model-theft '
                  'campaign exploiting a weakened isolation boundary.'),
    },
    {
        'name': 'HARDWARE_ATTACK_UNDER_THERMAL_COVER',
        'required': {'GPUTHOR_PRECURSOR_PREDICTED', 'THERMAL_EVENT_PREDICTED'},
        'severity': 'CRITICAL',
        'story': ('ECC-break precursor co-occurring with a predicted thermal '
                  'event: fault-injection attacks are easier in unstable '
                  'thermal states; the combination warrants immediate review.'),
    },
]


class SecurityCorrelator:
    """
    Consumes agent alerts, emits correlated incidents.

    Feed every alert from the swarm's ingest() into observe(alert). Call
    check_incidents() (or read the return of observe) to get any incidents
    whose rule conditions are currently satisfied within the window.
    """

    def __init__(self, window_seconds=30.0, time_fn=time.time):
        self.window_seconds = window_seconds
        self._time_fn = time_fn
        # recent alerts as (timestamp, alert_type, alert)
        self._recent = collections.deque()
        self._fired_incident_keys = collections.deque(maxlen=200)
        self.incident_count = 0

    def _prune(self, now):
        cutoff = now - self.window_seconds
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

    def observe(self, alert: dict) -> list:
        """Record one alert; return any incidents that fire as a result."""
        now = self._time_fn()
        atype = alert.get('type')
        if not atype:
            return []
        self._recent.append((now, atype, alert))
        self._prune(now)
        return self._evaluate(now)

    def _evaluate(self, now) -> list:
        present_types = {t for (_, t, _) in self._recent}
        incidents = []
        for rule in CORRELATION_RULES:
            if rule['required'].issubset(present_types):
                # De-dupe: don't re-fire the same rule for the same set of
                # contributing alert types within the current window.
                key = (rule['name'], frozenset(rule['required']))
                if key in self._fired_incident_keys:
                    continue
                contributing = [a for (_, t, a) in self._recent
                                if t in rule['required']]
                self._fired_incident_keys.append(key)
                self.incident_count += 1
                incident = {
                    'type': 'CORRELATED_INCIDENT',
                    'incident': rule['name'],
                    'severity': rule['severity'],
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'triggering_alert_types': sorted(rule['required']),
                    'contributing_alerts': contributing,
                    'window_seconds': self.window_seconds,
                    'story': rule['story'],
                    'agent': 'SecurityCorrelator',
                    'recommended_action': (
                        "Treat as a single high-priority incident. Evacuate/"
                        "isolate the affected GPU per the gated remediation "
                        "policy and preserve state for forensics. This is a "
                        "correlation of predictive signals, not a confirmed "
                        "breach -- investigate before destructive action."
                    ),
                    'note': ('Simulation-based. Correlation rule is a '
                             'hypothesis about co-occurring signatures, not '
                             'validated against real incident data.'),
                }
                print(f"[SWARM CORRELATOR] CORRELATED_INCIDENT {rule['name']} "
                      f"({rule['severity']}) from {sorted(rule['required'])}")
                incidents.append(incident)
        return incidents

    def get_stats(self) -> dict:
        return {
            'component': 'SecurityCorrelator',
            'window_seconds': self.window_seconds,
            'alerts_in_window': len(self._recent),
            'incidents_fired': self.incident_count,
            'rules': [r['name'] for r in CORRELATION_RULES],
        }


if __name__ == "__main__":
    print("=" * 55)
    print("Watchdog Swarm — Security Correlation Layer")
    print("Simulation test")
    print("=" * 55)

    # Deterministic fake clock so the demo is reproducible.
    clock = {'t': 1000.0}
    corr = SecurityCorrelator(window_seconds=30.0, time_fn=lambda: clock['t'])

    print("\n[1] Single ECC-break precursor alone -- no incident")
    out = corr.observe({'type': 'GPUTHOR_PRECURSOR_PREDICTED', 'severity': 'WARNING'})
    print("   incidents:", [i['incident'] for i in out])

    print("\n[2] Micro-burst arrives within window -> COORDINATED_WEIGHT_TAMPER")
    clock['t'] += 5
    out = corr.observe({'type': 'MICRO_BURST_PATTERN', 'severity': 'WARNING'})
    print("   incidents:", [i['incident'] for i in out])

    print("\n[3] Same pair again in window -> de-duped, no re-fire")
    clock['t'] += 2
    out = corr.observe({'type': 'GPUTHOR_PRECURSOR_PREDICTED', 'severity': 'WARNING'})
    print("   incidents:", [i['incident'] for i in out])

    print("\nCorrelator stats:", corr.get_stats())
