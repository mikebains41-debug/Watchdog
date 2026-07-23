# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
tests/test_validate_swarm_prediction.py

Tests scripts/validate_swarm_prediction.py's own correctness -- the
trial generators and the scoring/aggregation math -- using injectable
fake agents with known, controlled behavior. This is deliberately
separate from testing whether the REAL GhostPowerPredictor performs
well; a buggy test harness could produce a falsely reassuring result
regardless of the real agent's quality, so the harness itself needs
its own proof.

Run: python tests/test_validate_swarm_prediction.py
"""

import sys
import os
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scripts.validate_swarm_prediction import (
    generate_clean_trial,
    generate_event_trial,
    run_trial,
    score_trials,
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


def test_clean_trial_has_no_declining_trend():
    """Clean trials should show no SYSTEMATIC power decline -- checked
    over many trials. A pure random walk with these step sizes is
    statistically expected to occasionally drift by a large amount
    purely by chance (basic random-walk variance, not a bug) -- the
    threshold below allows for that expected rate rather than demanding
    an unrealistic zero, which would only pass if the generator were
    secretly less random than it claims to be."""
    rng = random.Random(1)
    declining_count = 0
    n = 50
    for _ in range(n):
        samples, event = generate_clean_trial(rng)
        check("clean trial reports no true event", event is None)
        first_10_avg = sum(s['power_watts'] for s in samples[:10]) / 10
        last_10_avg = sum(s['power_watts'] for s in samples[-10:]) / 10
        if (first_10_avg - last_10_avg) > 100:  # a huge, event-like drop
            declining_count += 1
    check("large event-like drops are RARE in clean trials (allowing "
          "for genuine random-walk variance, not demanding an "
          "unrealistic zero)",
          declining_count <= 10, f"{declining_count}/{n} had a >100W drop "
          f"(expected occasionally, not systematically)")


def test_event_trial_shows_real_precursor_signature_after_injection():
    """The injected event must actually exhibit the documented
    signature -- power ramping down, memory clock staying locked --
    after event_start, and NOT before it."""
    rng = random.Random(2)
    samples, event_start, ramp_rate = generate_event_trial(rng)

    check("event_start is a real index within the trial",
          0 < event_start < len(samples), f"got {event_start}")
    check("ramp_rate is within the expected default range",
          1.0 <= ramp_rate <= 18.0, f"got {ramp_rate}")

    pre_event_powers = [s['power_watts'] for s in samples[:event_start]]
    post_event_powers = [s['power_watts'] for s in samples[event_start:]]
    check("power is measurably lower well after the event than before it "
          "(the ramp actually happened)",
          post_event_powers[-1] < pre_event_powers[-1] - 20,
          f"pre-event last={pre_event_powers[-1]}, post-event last={post_event_powers[-1]}")

    post_event_mem = [s['mem_clock_mhz'] for s in samples[event_start:]]
    check("memory clock stays locked (near 1593, the documented value) "
          "throughout the post-event window, not drifting toward zero",
          all(1580 <= m <= 1610 for m in post_event_mem),
          f"got range {min(post_event_mem)}-{max(post_event_mem)}")


def test_randomization_actually_varies_across_calls():
    """Confirm event_start and ramp_rate genuinely differ across
    trials -- if this always returned the same values, it would just be
    the old scripted demo with extra steps."""
    rng = random.Random(3)
    starts = set()
    ramps = set()
    for _ in range(20):
        _, event_start, ramp_rate = generate_event_trial(rng)
        starts.add(event_start)
        ramps.add(round(ramp_rate, 1))
    check("event_start varies across trials, not a fixed scripted value",
          len(starts) > 1, f"got {starts}")
    check("ramp_rate varies across trials, not a fixed scripted value",
          len(ramps) > 1, f"got {ramps}")


class _AlwaysFiresImmediately:
    """Fake agent: fires on every single sample. Used to prove the
    scoring math correctly computes a 100% false positive rate when
    that's genuinely what happens."""
    def __init__(self, gpu_id=0):
        pass
    def update(self, telemetry):
        return {'type': 'FAKE_ALWAYS_FIRES'}


class _NeverFires:
    """Fake agent: never fires. Used to prove the scoring math
    correctly computes 0% true positive rate and 0% false positive
    rate when that's genuinely what happens."""
    def __init__(self, gpu_id=0):
        pass
    def update(self, telemetry):
        return None


class _FiresAtFixedSampleIndex:
    """Fake agent: fires exactly once, at a known fixed sample index.
    Used to prove lag calculation is arithmetically correct."""
    def __init__(self, gpu_id=0, fire_at=50):
        self.fire_at = fire_at
        self.count = -1
    def update(self, telemetry):
        self.count += 1
        if self.count == self.fire_at:
            return {'type': 'FAKE_FIXED_FIRE'}
        return None


def test_scoring_always_fires_agent_gives_100pct_false_positive_rate():
    results = score_trials(n_clean=10, n_event=0, agent_factory=_AlwaysFiresImmediately)
    check("an agent that always fires produces exactly 100% false "
          "positive rate, not some other value",
          results['false_positive_rate'] == 1.0, f"got {results['false_positive_rate']}")


def test_scoring_never_fires_agent_gives_zero_rates():
    results = score_trials(n_clean=10, n_event=10, agent_factory=_NeverFires)
    check("an agent that never fires produces exactly 0% false positive rate",
          results['false_positive_rate'] == 0.0, f"got {results['false_positive_rate']}")
    check("an agent that never fires produces exactly 0% true positive rate",
          results['true_positive_rate'] == 0.0, f"got {results['true_positive_rate']}")
    check("an agent that never fires produces no lag data (not zero, "
          "genuinely undefined -- there's nothing to average)",
          results['lag_samples_mean'] is None, f"got {results['lag_samples_mean']}")


def test_scoring_lag_calculation_is_arithmetically_correct():
    """A fake agent that always fires at sample 50 -- lag should equal
    exactly (50 - event_start) for every trial, computed correctly."""
    def factory(gpu_id=0):
        return _FiresAtFixedSampleIndex(gpu_id=gpu_id, fire_at=50)

    results = score_trials(n_clean=0, n_event=20, agent_factory=factory, seed=7)
    for r in results['event_results']:
        expected_lag = 50 - r['event_start']
        check(f"lag for event_start={r['event_start']} is exactly "
              f"{expected_lag} (50 - event_start), computed correctly",
              r['fired'] and r['lag_samples'] == expected_lag,
              f"got {r}")


def test_run_trial_returns_none_when_agent_never_fires():
    rng = random.Random(4)
    samples, _ = generate_clean_trial(rng)
    fired_at = run_trial(samples, agent_factory=_NeverFires)
    check("run_trial returns None when the agent never fires, not a "
          "fabricated index", fired_at is None)


def test_run_trial_returns_first_firing_index_only():
    """An agent that fires on every sample should still only report
    the FIRST firing index -- run_trial exists to find onset, not count
    every subsequent alert."""
    rng = random.Random(5)
    samples, _ = generate_clean_trial(rng, n_samples=20)
    fired_at = run_trial(samples, agent_factory=_AlwaysFiresImmediately)
    check("run_trial reports index 0 for an agent that fires on every "
          "sample (the first one), not the last or some other index",
          fired_at == 0, f"got {fired_at}")


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
