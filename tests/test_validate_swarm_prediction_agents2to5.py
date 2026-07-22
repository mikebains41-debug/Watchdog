"""
tests/test_validate_swarm_prediction_agents2to5.py

Tests for scripts/validate_swarm_prediction_agents2to5.py: spot-checks
that each agent's generators produce genuine, varying randomized
trials (not fixed scripted shapes), and proves the shared score_agent
scoring math is correct using injectable fake agents -- independent of
whether any real agent performs well.

Run: python tests/test_validate_swarm_prediction_agents2to5.py
"""

import sys
import os
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scripts.validate_swarm_prediction_agents2to5 import (
    agent2_generate_clean, agent2_generate_event,
    agent3_generate_clean, agent3_generate_event,
    agent4_generate_clean, agent4_generate_event,
    agent5_generate_clean, agent5_generate_event,
    run_trial, score_agent, AGENTS,
)

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def test_agent2_event_shows_real_decline():
    rng = random.Random(1)
    samples, event_start = agent2_generate_event(rng, severity=3e9)
    pre = [s['cei_flops_per_joule'] for s in samples[:event_start]]
    post = [s['cei_flops_per_joule'] for s in samples[event_start:]]
    check("agent2 event: CEI measurably lower after injection than before",
          post[-1] < pre[-1] * 0.5, f"pre_last={pre[-1]:.2e}, post_last={post[-1]:.2e}")


def test_agent2_randomization_varies():
    rng = random.Random(2)
    starts = {agent2_generate_event(rng, severity=1e9)[1] for _ in range(15)}
    check("agent2: event_start varies across calls", len(starts) > 1, f"got {starts}")


def test_agent3_event_shows_real_temp_rise():
    rng = random.Random(3)
    samples, event_start = agent3_generate_event(rng, severity=0.6)
    pre = [s['temp_c'] for s in samples[:event_start]]
    post = [s['temp_c'] for s in samples[event_start:]]
    check("agent3 event: temperature measurably higher after injection",
          post[-1] > pre[-1] + 10, f"pre_last={pre[-1]:.1f}, post_last={post[-1]:.1f}")


def test_agent4_event_shows_real_vram_growth():
    rng = random.Random(4)
    samples, event_start = agent4_generate_event(rng, severity=0.9)
    pre = [s['vram_used_mb'] for s in samples[:event_start]]
    post = [s['vram_used_mb'] for s in samples[event_start:]]
    check("agent4 event: VRAM measurably higher after injection",
          post[-1] > pre[-1] + 30, f"pre_last={pre[-1]:.1f}, post_last={post[-1]:.1f}")


def test_agent5_event_shows_real_compliance_degradation():
    rng = random.Random(5)
    samples, event_start = agent5_generate_event(rng, severity=1.3)
    pre_iso = [s['isolation_score'] for s in samples[:event_start]]
    post_iso = [s['isolation_score'] for s in samples[event_start:]]
    check("agent5 event: isolation score measurably lower after injection",
          post_iso[-1] < pre_iso[-1] - 0.05, f"pre_last={pre_iso[-1]:.3f}, post_last={post_iso[-1]:.3f}")


def test_all_clean_generators_report_no_event():
    """None of the 4 clean generators should accept an event_start
    parameter at all -- they're structurally incapable of injecting an
    event, not just configured not to."""
    import inspect
    for fn in [agent2_generate_clean, agent3_generate_clean,
               agent4_generate_clean, agent5_generate_clean]:
        params = inspect.signature(fn).parameters
        check(f"{fn.__name__}: no severity/event_start parameter exists "
              f"(structurally cannot inject an event)",
              'severity' not in params and 'event_start' not in params,
              f"params: {list(params)}")


class _AlwaysFires:
    def update(self, telemetry):
        return {'type': 'FAKE'}


class _NeverFires:
    def update(self, telemetry):
        return None


def _dummy_clean(rng, n=20):
    return [{'x': rng.random()} for _ in range(n)]


def _dummy_event(rng, severity, n=20):
    event_start = rng.randint(5, 15)
    return [{'x': rng.random()} for _ in range(n)], event_start


def test_score_agent_always_fires_gives_100pct_fpr():
    results = score_agent(_dummy_clean, _dummy_event, _AlwaysFires,
                           n_clean=10, n_event=0)
    check("score_agent: an always-firing agent gives exactly 100% FPR",
          results['false_positive_rate'] == 1.0, f"got {results['false_positive_rate']}")


def test_score_agent_never_fires_gives_zero_rates():
    results = score_agent(_dummy_clean, _dummy_event, _NeverFires,
                           n_clean=10, n_event=10)
    check("score_agent: a never-firing agent gives exactly 0% FPR",
          results['false_positive_rate'] == 0.0, f"got {results['false_positive_rate']}")
    check("score_agent: a never-firing agent gives exactly 0% TPR",
          results['true_positive_rate'] == 0.0, f"got {results['true_positive_rate']}")


def test_score_agent_tier_breakdown_sums_to_total():
    """The 3 severity tiers should partition the event trials exactly --
    no trial double-counted or dropped."""
    results = score_agent(_dummy_clean, _dummy_event, _NeverFires,
                           n_clean=0, n_event=30)
    total_in_tiers = sum(t['n'] for t in results['tier_stats'].values())
    check("score_agent: severity tiers partition all event trials exactly",
          total_in_tiers == 30, f"got {total_in_tiers}, expected 30")


def test_agents_registry_all_have_required_keys():
    """Confirm the AGENTS dict driving main()'s reporting has a
    complete, correctly-shaped entry for every agent."""
    required_keys = {'name', 'factory', 'clean_fn', 'event_fn',
                      'severity_range', 'severity_unit'}
    for key, spec in AGENTS.items():
        check(f"AGENTS['{key}']: has all required keys",
              required_keys.issubset(spec.keys()),
              f"missing: {required_keys - spec.keys()}")
        check(f"AGENTS['{key}']: severity_range is a valid (low, high) pair",
              spec['severity_range'][0] < spec['severity_range'][1],
              f"got {spec['severity_range']}")


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for t in tests:
        try:
            t()
        except Exception as e:
            check(t.__name__, False, f"EXCEPTION {e!r}")

    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print("\nFailures:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
