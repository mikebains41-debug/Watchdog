# Wiring the Security Swarm into swarm_orchestrator.py

Five small edits to `intelligence/swarm/swarm_orchestrator.py`. The three
agents and the correlator are already tested standalone (15/15). These
edits make the existing orchestrator run them alongside the original 5
agents and correlate their output. Nothing about the original 5 changes.

Make the edits by hand in the GitHub web editor (or `nano`), matching the
existing style. Each is an ADD next to existing lines — no deletions.

---

## Edit 1 — add the imports

Find the block of agent imports near the top:

    from intelligence.swarm.agent5_eu_ai_act_compliance_forecaster import EUAIActComplianceForecaster

Add immediately after it:

    from intelligence.swarm.agent6_rowhammer_precursor_predictor import RowhammerPrecursorPredictor
    from intelligence.swarm.agent7_cryptojacking_onset_predictor import CryptojackingOnsetPredictor
    from intelligence.swarm.agent8_model_extraction_precursor_predictor import ModelExtractionPrecursorPredictor
    from intelligence.swarm.security_correlator import SecurityCorrelator

---

## Edit 2 — instantiate the agents + correlator in __init__

Find, inside `__init__`:

    self.agent5 = EUAIActComplianceForecaster(gpu_id=gpu_id)

Add immediately after it:

    # Security prediction agents (6-8) + correlation layer
    self.agent6 = RowhammerPrecursorPredictor(gpu_id=gpu_id)
    self.agent7 = CryptojackingOnsetPredictor(gpu_id=gpu_id)
    self.agent8 = ModelExtractionPrecursorPredictor(gpu_id=gpu_id)
    self.correlator = SecurityCorrelator(window_seconds=30.0)

---

## Edit 3 — add them to the self.agents list

Find:

        self.agents = [
            self.agent1,
            self.agent2,
            self.agent3,
            self.agent4,
            self.agent5
        ]

Replace the closing lines so it reads:

        self.agents = [
            self.agent1,
            self.agent2,
            self.agent3,
            self.agent4,
            self.agent5,
            self.agent6,
            self.agent7,
            self.agent8
        ]

(Just add the comma after self.agent5 and the three new lines.)

Optional: update the print line `print(f"[SWARM] 5 agents active")` to
`print(f"[SWARM] 8 agents active (5 operational + 3 security) + correlator")`.

---

## Edit 4 — run agents 6-8 and the correlator inside ingest()

Find, inside `ingest()`:

            # Agent 5 — EU AI Act
            a5 = self.agent5.update(telemetry)
            if a5:
                alerts.append(a5)

Add immediately after it (before the `with self.lock:` block):

            # Agent 6 — Rowhammer / ECC-break precursor
            a6 = self.agent6.update(telemetry)
            if a6:
                alerts.append(a6)

            # Agent 7 — Cryptojacking / covert-compute onset
            a7 = self.agent7.update(telemetry)
            if a7:
                alerts.append(a7)

            # Agent 8 — Model-extraction / abnormal-inference precursor
            a8 = self.agent8.update(telemetry)
            if a8:
                alerts.append(a8)

            # Correlation layer — escalate co-occurring alerts into incidents
            incidents = []
            for alert in alerts:
                incidents.extend(self.correlator.observe(alert))
            alerts.extend(incidents)

Note: the correlator also needs to see alerts from the ORIGINAL agents
(e.g. GHOST_POWER_PREDICTED, TENANT_ISOLATION_RISK, THERMAL_EVENT_PREDICTED)
to correlate them with the security ones. The loop above feeds it every
alert fired this sample, so that already works — the original agents'
alert `type` strings are what the correlation rules key on.

---

## Edit 5 — surface the new components in get_swarm_summary()

Find, inside `get_swarm_summary()`:

                'agent5_compliance': self.agent5.get_stats(),
            },

Change to:

                'agent5_compliance': self.agent5.get_stats(),
                'agent6_rowhammer': self.agent6.get_stats(),
                'agent7_cryptojacking': self.agent7.get_stats(),
                'agent8_model_extraction': self.agent8.get_stats(),
                'correlator': self.correlator.get_stats(),
            },

---

## Verify after editing

    cd ~/Watchdog
    python3 tests/test_security_swarm.py          # expect PASSED: 15  FAILED: 0
    python3 intelligence/swarm/swarm_orchestrator.py   # should run all 8 agents, no import error

If the orchestrator's __main__ demo runs without an ImportError and the
test suite passes, the wiring is correct.

---

## Correlation rules currently active

The correlator escalates these co-occurring pairs (within a 30s window)
into single CRITICAL incidents:

- COORDINATED_WEIGHT_TAMPER = GPUTHOR_PRECURSOR_PREDICTED + MICRO_BURST_PATTERN
- STEALTHY_RESOURCE_THEFT   = COVERT_COMPUTE_ONSET_PREDICTED + GHOST_POWER_PREDICTED
- IP_EXFILTRATION_CAMPAIGN  = MODEL_EXTRACTION_PRECURSOR_PREDICTED + TENANT_ISOLATION_RISK
- HARDWARE_ATTACK_UNDER_THERMAL_COVER = GPUTHOR_PRECURSOR_PREDICTED + THERMAL_EVENT_PREDICTED

Two of these deliberately pair a NEW security agent with an ORIGINAL swarm
agent (ghost-power, tenant-isolation, thermal) — that's the swarm
correlating across its operational and security halves.

NOTE (carry into any external material): everything here is
simulation-based and requires real hardware validation. Precursor
signatures and correlation rules are hypotheses grounded in published
attack research, not tuned against real incident data.
