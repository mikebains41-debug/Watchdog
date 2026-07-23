# Author: Manmohan (Mike) Bains -- Watchdog AIDR
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from telemetry.sampler import DeltaTimedSampler

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def make_fake_clock():
    state = {'ns': 0}
    def clock():
        return state['ns']
    def advance(ms):
        state['ns'] += int(ms * 1_000_000)
    return clock, advance


def test_first_sample_has_no_interval():
    clock, advance = make_fake_clock()
    s = DeltaTimedSampler(lambda: {'power.draw': 80.0}, clock_fn=clock)
    row = s.sample()
    check("first sample: actual_interval_ms is None (no prior reference)",
          row['actual_interval_ms'] is None)


def test_measures_real_delta_not_requested_rate():
    clock, advance = make_fake_clock()
    s = DeltaTimedSampler(lambda: {'power.draw': 80.0}, clock_fn=clock)
    s.sample()
    advance(500)
    row = s.sample()
    check("measures actual 500ms delta",
          row['actual_interval_ms'] is not None
          and abs(row['actual_interval_ms'] - 500.0) < 0.01,
          f"got {row['actual_interval_ms']}")


def test_achieved_rate_reflects_measured_reality():
    clock, advance = make_fake_clock()
    s = DeltaTimedSampler(lambda: {}, clock_fn=clock)
    s.sample()
    for _ in range(5):
        advance(500)
        s.sample()
    hz = s.achieved_rate_hz()
    check("achieved_rate_hz reports ~2Hz from measured deltas",
          hz is not None and 1.9 <= hz <= 2.1, f"got {hz}")


def test_stats_empty_before_any_deltas():
    s = DeltaTimedSampler(lambda: {})
    st = s.stats()
    check("stats() before any deltas: samples=0, achieved_hz=None",
          st['samples'] == 0 and st['achieved_hz'] is None, f"got {st}")


def test_variable_intervals_produce_correct_stats():
    clock, advance = make_fake_clock()
    s = DeltaTimedSampler(lambda: {}, clock_fn=clock)
    s.sample()
    for gap in (100, 900, 500):
        advance(gap)
        s.sample()
    st = s.stats()
    check("stats: min_ms reflects smallest actual gap",
          abs(st['min_ms'] - 100.0) < 0.01, f"got {st}")
    check("stats: max_ms reflects largest actual gap",
          abs(st['max_ms'] - 900.0) < 0.01, f"got {st}")


def test_row_not_mutated_incorrectly_on_reused_dict():
    clock, advance = make_fake_clock()
    calls = {'n': 0}
    def fn():
        calls['n'] += 1
        return {'call': calls['n']}
    s = DeltaTimedSampler(fn, clock_fn=clock)
    r1 = s.sample()
    advance(10)
    r2 = s.sample()
    check("each row carries its own call identity, no cross-contamination",
          r1['call'] == 1 and r2['call'] == 2, f"got {r1}, {r2}")


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
