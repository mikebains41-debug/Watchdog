#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog Swarm Intelligence — Response Pipeline

Chains the swarm's per-sample output through the full response stack in
one call, WITHOUT modifying the orchestrator:

    swarm.ingest(telemetry)  ->  alerts + correlated incidents
        -> RemediationCoordinator.build_plan(...)  ->  gated/auto action plan
        -> LLMIncidentInvestigator.investigate(...) ->  per-incident report

This is additive: it consumes what WatchdogSwarm.ingest() already returns
and produces a unified response bundle. The orchestrator stays exactly as
committed (8 agents + correlator); this layer sits on top.

Nothing here executes an action. The remediation plan is handed to the
existing gated remediation engine; the investigator only proposes. This
module is the coordination seam, not an executor.

NOTE: Simulation-based. Requires real hardware validation.
"""
from datetime import datetime, timezone

from intelligence.swarm.remediation_coordinator import RemediationCoordinator
from intelligence.swarm.llm_incident_investigator import LLMIncidentInvestigator


class SwarmResponsePipeline:
    """
    Wraps a WatchdogSwarm-like object (anything with .ingest(telemetry)
    returning a list of alert/incident dicts) and runs each sample's
    output through remediation planning + incident investigation.
    """

    def __init__(self, swarm, investigator_api_client=None):
        self.swarm = swarm
        self.remediation = RemediationCoordinator()
        self.investigator = LLMIncidentInvestigator(api_client=investigator_api_client)
        self.samples = 0
        self.plans = 0
        self.investigations = 0

    def process(self, telemetry: dict) -> dict:
        """
        Feed one telemetry sample all the way through the stack.
        Returns a response bundle: the raw alerts, the remediation plan,
        and any incident investigations.
        """
        alerts = self.swarm.ingest(telemetry)
        self.samples += 1

        bundle = {
            "type": "SWARM_RESPONSE_BUNDLE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alerts": alerts,
            "remediation_plan": None,
            "investigations": [],
        }

        if not alerts:
            return bundle

        # Build a single de-conflicted, gated remediation plan for this tick.
        plan = self.remediation.build_plan(alerts)
        self.plans += 1
        bundle["remediation_plan"] = plan

        # Investigate every CORRELATED_INCIDENT (the escalated, multi-signal
        # events worth a written analysis). Individual WARNINGs get a plan
        # but not a full investigation, to keep the investigator focused on
        # real incidents rather than every single alert.
        for alert in alerts:
            if alert.get("type") == "CORRELATED_INCIDENT":
                report = self.investigator.investigate(
                    alert, alert.get("contributing_alerts", [])
                )
                self.investigations += 1
                bundle["investigations"].append(report)

        return bundle

    def get_stats(self) -> dict:
        return {
            "component": "SwarmResponsePipeline",
            "samples_processed": self.samples,
            "plans_built": self.plans,
            "investigations": self.investigations,
            "remediation": self.remediation.get_stats(),
            "investigator": self.investigator.get_stats(),
        }


if __name__ == "__main__":
    # Minimal fake swarm so this runs without the full agent stack.
    class _FakeSwarm:
        def __init__(self):
            self._tick = 0
        def ingest(self, telemetry):
            self._tick += 1
            if self._tick == 3:
                # simulate a correlated incident + its contributing alerts
                return [
                    {"type": "GPUTHOR_PRECURSOR_PREDICTED", "severity": "WARNING", "gpu": 1},
                    {"type": "MICRO_BURST_PATTERN", "severity": "WARNING", "gpu": 1},
                    {"type": "CORRELATED_INCIDENT", "severity": "CRITICAL", "gpu": 1,
                     "incident": "COORDINATED_WEIGHT_TAMPER",
                     "triggering_alert_types": ["GPUTHOR_PRECURSOR_PREDICTED", "MICRO_BURST_PATTERN"],
                     "story": "ECC-break precursor with hidden micro-burst compute.",
                     "contributing_alerts": [
                         {"type": "GPUTHOR_PRECURSOR_PREDICTED", "severity": "WARNING", "gpu": 1},
                         {"type": "MICRO_BURST_PATTERN", "severity": "WARNING", "gpu": 1},
                     ]},
                ]
            return []

    print("=" * 55)
    print("Watchdog Swarm — Response Pipeline (offline demo)")
    print("=" * 55)
    pipe = SwarmResponsePipeline(_FakeSwarm())
    for i in range(4):
        b = pipe.process({"tick": i})
        if b["alerts"]:
            print(f"\nTick {i}: {len(b['alerts'])} alerts")
            plan = b["remediation_plan"]
            print(f"  plan: {plan['auto_dispatch_count']} auto, "
                  f"{plan['gated_request_count']} gated")
            for inv in b["investigations"]:
                print(f"  investigation: {inv['likely_attack']} "
                      f"-> propose {inv['proposed_action']}")
    print("\nStats:", pipe.get_stats())
