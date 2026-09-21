# Watchdog Swarm — Coordination Layer

Five files. All four phone-doable items from the plan. No GPU required.

## Install

```bash
cd ~/Watchdog
cp swarm_qualification.py scripts/
cp swarm_consensus.py swarm_derived_fields.py intelligence/swarm/
cp swarm_agents.json intelligence/swarm/
cp test_swarm_consensus.py tests/
```

Then add to `TEST_FILES` in `tests/run_all.py` (explicit list, not a glob —
deliberate, so GPU-dependent tests don't silently join the automated suite):

```python
"test_swarm_consensus.py",
```

## Run

```bash
cd ~/Watchdog
python3 tests/test_swarm_consensus.py            # 43 tests, ~2s, no GPU
python3 scripts/swarm_qualification.py --discover-only
python3 scripts/swarm_qualification.py --json evidence/swarm_qualification.json
```

The full qualification run constructs a fresh agent per trial (agents carry
learned baselines; reusing one contaminates trial N with trial N-1). At the
defaults that is 8 agents × 400 trials × 18 samples. Start smaller:

```bash
python3 scripts/swarm_qualification.py --n-clean 50 --n-event 50 --n-pairwise 40
```

## What each file does

**`swarm_qualification.py`** — answers four questions in order.

1. *Discovery.* Which agents import, construct, and have an `update` method.
   Every failure is reported with its exception rather than crashing the run.
2. *TPR/FPR per agent*, on randomized synthetic trials with fresh noise and
   randomized severity per trial. Separates `STRUCTURALLY_SILENT` (never
   fires on any input — a telemetry problem) from `BELOW_BAR` (fires, but
   badly — an accuracy problem). Those need opposite fixes.
3. *Pairwise agreement.* Agents agreeing above 95% are functionally one agent
   and should not both carry weight in a vote they're sharing.
4. *Ensemble vs best single agent.* **The pass/fail test for the whole swarm.**
   If weighted consensus doesn't beat your single best detector on the same
   corpus, the coordination layer is adding noise, and more agents will
   amplify that rather than fix it.

**`swarm_consensus.py`** — Layers 1–3.

- Layer 1: uniform `Emission` record. Agents never call each other, so a
  false positive stays attributable to exactly one agent. That attribution is
  what makes the Layer 3 weights defensible.
- Layer 2: group by GPU + time window, with **per-agent dedupe**. A
  sub-second agent firing 60 times must not outvote a minutes-tier agent
  firing once — otherwise the vote measures sampling rate, not evidence.
- Layer 3: weighted consensus, weights = measured TPR − FPR, loaded from the
  qualification JSON. Unqualified agents get exactly 0.0, never a small
  weight.

Layers 4 and 5 are deliberately absent — build the root-cause table when a
15-agent pool produces real multi-signal incidents, not against imagined ones.
Nothing here executes anything; Layer 6 human approval is unchanged.

**`swarm_derived_fields.py`** — three of EUAIActComplianceForecaster's four
blockers, computed from telemetry you already collect: `ghost_power_pct`,
`crash_count`, `isolation_score`. It does **not** fabricate
`cei_flops_per_joule`, which no passive field provides. Every field returns
`None` when its inputs are absent — never 0.0, because `_shared.py`'s `_f()`
already showed where a false zero leads.

**`swarm_agents.json`** — the registry. TenantIsolationRiskScorer marked
`INACTIVE_MISSING_TELEMETRY` with both reasons recorded. Weights come only
from measured runs.

**`test_swarm_consensus.py`** — 43 tests, injectable fakes with known
behaviour, so the scoring math is proven correct independently of whether any
real agent performs well.

## Correction (2026-09-21)

An earlier version of this section said the harness had reproduced the
2026-09-19 GhostPowerDetector false positive. That was wrong. The "0% FPR
cold-idle / 100% context-alive" result came from a stand-in stub used to
test the harness, not from Watchdog's real GhostPowerPredictor. Against the
real agent, agent1 measured 100% TPR and 0% FPR, with no difference between
cold-idle and context-alive rows.

The real 2026-09-19 false positive was in the reactive GhostPowerDetector
(detection/), with a different signature: it reported power about 45W above
a 78.4W floor on a GPU nvidia-smi read at 78.98W five times running. That
power did not exist on that GPU, which points at the telemetry reaching the
detector (stale or wrong-GPU row), not at the idle floor. Still open.

The harness keeps its cold-idle / context-alive split as methodology: a
cold-only negative-control corpus would hide a floor problem if one existed.
It has not found one in a real agent.

## Sequence

1. `python3 scripts/swarm_qualification.py --json evidence/swarm_qualification.json`
   Qualifies agents 6, 7, 8 — already written, never positive-controlled.
   Could take the pool from 2 to 5 with no new code.
2. Fix agent1's floor using the per-state FPR output.
3. Wire `DerivedFieldEnricher` into the telemetry path.
4. `intelligence/cei_benchmark.py` on real hardware — the one item that needs
   a GPU. Unblocks agents 2 and 5 together. Pool goes to 7.
5. Build Layers 4–5 only after the ensemble test passes.

Going 2 → 7 with agents already written beats going 5 → 30 with agents that
aren't.
