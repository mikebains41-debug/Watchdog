#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
scripts/validate_swarm_prediction.py

Non-circular validation for the swarm prediction agents (currently:
GhostPowerPredictor -- the same pattern extends to the other 4). Every
existing demo in intelligence/swarm/*.py hand-scripts telemetry shaped
to trigger that exact agent's own coded thresholds -- proving the
arithmetic recognizes a pattern built to match it, not that the agent
predicts anything on data it wasn't tuned against. This closes that
specific gap.

METHODOLOGY:
  1. Generate many independent trials. Each is EITHER:
     - a "clean" trial: realistic random noise for the full duration,
       no real event, not curated to avoid the agent's thresholds, or
     - an "event" trial: realistic random noise, with a ghost-power
       precursor signature injected at a RANDOM position, with
       RANDOMIZED parameters (ramp rate, event start time) -- not one
       fixed scripted shape replayed every time.
  2. Feed each trial through a FRESH agent instance -- no state carried
     between trials.
  3. Score: did the agent fire during an event trial, and how many
     samples after the true injection point? Did it fire during a
     clean trial (false positive)?
  4. Aggregate across all trials: false positive rate, true positive
     rate, lag distribution.

agent_factory is injectable throughout specifically so the SCORING
MATH can be tested against a fake agent with known, controlled
behavior -- independent of whether the real GhostPowerPredictor is any
good. See tests/test_validate_swarm_prediction.py.

WHAT THIS PROVES: whether GhostPowerPredictor's scoring logic
generalizes across a RANGE of plausible variations of the documented
precursor pattern, and how often realistic random noise fools it --
materially stronger than "the demo fires when fed data written to fire
it."

WHAT THIS DOES NOT PROVE: whether the documented precursor pattern
itself (power ramp + memory clock lock) actually precedes real ghost
power events on real hardware with the claimed 30-60s lead time, or
whether real GPU telemetry noise resembles this synthetic noise model.
That requires real, timestamped ghost-power events from live hardware
-- unavailable in this environment. This script closes the "does the
code work as designed" gap. It does not and cannot close the "is the
design itself correct" gap.

STATUS: fully executable right now -- no GPU, no torch, no hardware
needed. Pure Python synthetic-data testing.

Usage:
  python3 scripts/validate_swarm_prediction.py
  python3 scripts/validate_swarm_prediction.py --n-clean 500 --n-event 500
"""

import argparse
import random
import statistics
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelligence.swarm.agent1_ghost_power_predictor import GhostPowerPredictor


def generate_clean_trial(rng, n_samples=120, base_power=350.0, base_util=90.0):
    """Realistic random noise, no injected event. NOT curated to avoid
    the agent's thresholds -- if the agent fires here, that's a genuine
    false positive, not an artifact of a rigged test."""
    samples = []
    power = base_power
    util = base_util
    for i in range(n_samples):
        power += rng.uniform(-8, 8)
        power = max(50, min(450, power))
        util += rng.uniform(-5, 5)
        util = max(0, min(100, util))
        mem_clock = 1593 + rng.uniform(-15, 15)
        temp = 70 + rng.uniform(-3, 3)
        samples.append({
            'power_watts': power, 'gpu_util': util,
            'mem_clock_mhz': mem_clock, 'temp_c': temp,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })
    return samples, None


def generate_event_trial(rng, n_samples=120, base_power=350.0, base_util=90.0,
                          min_event_start=40, max_event_start=90,
                          min_ramp=1.0, max_ramp=18.0):
    """Realistic random noise, with a randomized ghost-power precursor
    (documented pattern: power ramps down, memory clock stays locked)
    injected at a random position. Ramp rate and start time are
    randomized per-trial, not one fixed scripted shape.

    min_ramp defaults to 1.0 W/sample specifically to include gradual,
    marginal events, not just severe ones -- an earlier version of this
    function defaulted to 6-18 W/sample, and every value in that range
    already saturated the agent's own thresholds by sample 10
    regardless of severity, which produced a uniform, uninformative
    result (100% TPR, exactly 10 samples lag every time). Testing only
    obvious cases and calling that validation would have been the same
    mistake as the circular demos this script exists to fix, one level
    removed."""
    event_start = rng.randint(min_event_start, max_event_start)
    ramp_rate = rng.uniform(min_ramp, max_ramp)
    samples = []
    power = base_power
    util = base_util
    for i in range(n_samples):
        if i < event_start:
            power += rng.uniform(-8, 8)
            power = max(50, min(450, power))
            util += rng.uniform(-5, 5)
            util = max(0, min(100, util))
            mem_clock = 1593 + rng.uniform(-15, 15)
        else:
            into_event = i - event_start
            power = max(60, base_power - (into_event * ramp_rate) + rng.uniform(-4, 4))
            util = max(0, base_util - (into_event * 8) + rng.uniform(-3, 3))
            mem_clock = 1593 + rng.uniform(-8, 8)  # stays locked -- the real signature
        temp = 70 - (max(0, i - event_start) * 0.3) + rng.uniform(-3, 3)
        samples.append({
            'power_watts': power, 'gpu_util': util,
            'mem_clock_mhz': mem_clock, 'temp_c': temp,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })
    return samples, event_start, ramp_rate


def run_trial(samples, agent_factory=GhostPowerPredictor, gpu_id=0):
    """Fresh agent instance, feed the whole trial, return the index of
    the FIRST firing sample, or None if it never fired."""
    agent = agent_factory(gpu_id=gpu_id)
    fired_at = None
    for i, sample in enumerate(samples):
        result = agent.update(sample)
        if result and fired_at is None:
            fired_at = i
    return fired_at


def score_trials(n_clean=100, n_event=100, seed=42, agent_factory=GhostPowerPredictor,
                  min_ramp=1.0, max_ramp=18.0):
    rng = random.Random(seed)

    clean_fired = []
    for _ in range(n_clean):
        samples, _ = generate_clean_trial(rng)
        fired_at = run_trial(samples, agent_factory=agent_factory)
        clean_fired.append(fired_at is not None)

    event_results = []
    for _ in range(n_event):
        samples, event_start, ramp_rate = generate_event_trial(
            rng, min_ramp=min_ramp, max_ramp=max_ramp)
        fired_at = run_trial(samples, agent_factory=agent_factory)
        if fired_at is not None:
            event_results.append({'fired': True, 'fired_at': fired_at,
                                   'event_start': event_start, 'ramp_rate': ramp_rate,
                                   'lag_samples': fired_at - event_start})
        else:
            event_results.append({'fired': False, 'event_start': event_start,
                                   'ramp_rate': ramp_rate})

    false_positive_rate = (sum(clean_fired) / n_clean) if n_clean else None
    true_positive_rate = (sum(1 for r in event_results if r['fired']) / n_event) if n_event else None
    lags = [r['lag_samples'] for r in event_results if r['fired']]

    # Break down by severity tercile so a uniform aggregate can't hide
    # a real, honest weakness on gradual/marginal events.
    sorted_by_ramp = sorted(event_results, key=lambda r: r['ramp_rate'])
    third = max(1, len(sorted_by_ramp) // 3)
    tiers = {
        'gradual (lowest third of ramp rates)': sorted_by_ramp[:third],
        'moderate (middle third)': sorted_by_ramp[third:2 * third],
        'severe (highest third)': sorted_by_ramp[2 * third:],
    }
    tier_stats = {}
    for name, group in tiers.items():
        if not group:
            continue
        tpr = sum(1 for r in group if r['fired']) / len(group)
        ramp_range = (min(r['ramp_rate'] for r in group), max(r['ramp_rate'] for r in group))
        tier_lags = [r['lag_samples'] for r in group if r['fired']]
        tier_stats[name] = {
            'n': len(group), 'true_positive_rate': tpr,
            'ramp_rate_range_w_per_sample': ramp_range,
            'lag_samples_mean': statistics.mean(tier_lags) if tier_lags else None,
        }

    return {
        'n_clean_trials': n_clean,
        'n_event_trials': n_event,
        'false_positive_rate': false_positive_rate,
        'true_positive_rate': true_positive_rate,
        'lag_samples_mean': statistics.mean(lags) if lags else None,
        'lag_samples_median': statistics.median(lags) if lags else None,
        'tier_stats': tier_stats,
        'clean_fired': clean_fired,
        'event_results': event_results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--n-clean', type=int, default=100)
    parser.add_argument('--n-event', type=int, default=100)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--min-ramp', type=float, default=1.0,
                         help="Slowest injected ramp rate, W/sample")
    parser.add_argument('--max-ramp', type=float, default=18.0,
                         help="Fastest injected ramp rate, W/sample")
    args = parser.parse_args()

    print("=" * 70)
    print("NON-CIRCULAR VALIDATION: GhostPowerPredictor")
    print("Randomized synthetic trials, agent's own decision logic,")
    print("no hand-scripted trigger data")
    print("=" * 70)

    results = score_trials(n_clean=args.n_clean, n_event=args.n_event, seed=args.seed,
                            min_ramp=args.min_ramp, max_ramp=args.max_ramp)

    print(f"\nClean trials (no event): {results['n_clean_trials']}")
    print(f"  False positive rate: {results['false_positive_rate']*100:.1f}%")
    print(f"\nEvent trials (randomized injected precursor, ramp rate {args.min_ramp}-{args.max_ramp} W/sample): "
          f"{results['n_event_trials']}")
    print(f"  Overall true positive rate: {results['true_positive_rate']*100:.1f}%")
    if results['lag_samples_mean'] is not None:
        print(f"  Overall mean lag from true event start: {results['lag_samples_mean']:.1f} samples")

    print("\n  Broken down by severity (uniform aggregates can hide real "
          "weaknesses on gradual events):")
    for tier_name, stats in results['tier_stats'].items():
        rr = stats['ramp_rate_range_w_per_sample']
        lag = f"{stats['lag_samples_mean']:.1f}" if stats['lag_samples_mean'] is not None else "N/A"
        print(f"    {tier_name}: n={stats['n']}, ramp={rr[0]:.1f}-{rr[1]:.1f}W/sample, "
              f"TPR={stats['true_positive_rate']*100:.1f}%, mean lag={lag} samples")

    print("\nNOTE: 'samples' means telemetry samples, not seconds -- converting")
    print("to real lead time requires a real sample rate, not assumed here.")
    print("See tests/test_telemetry_sampler_wiring.py for the real measured rate.")
    print("\nThis proves the SCORING LOGIC generalizes across randomized")
    print("variations of the documented pattern, INCLUDING gradual/marginal")
    print("cases, not just obvious ones. It does NOT prove the pattern itself")
    print("precedes real ghost power events on real hardware -- that requires")
    print("real, timestamped hardware data.")


if __name__ == '__main__':
    main()
