"""
tests/test_precision_ghost_power_benchmark.py

Tests the LOGIC of scripts/precision_ghost_power_benchmark.py against
synthetic data: FLOPs counting, CEI computation, ghost-share computation,
and the hypothesis-check itself. This proves the arithmetic is correct.
It proves NOTHING about what real hardware actually measures -- that
requires running the script for real, which requires a GPU that does not
exist in the environment that wrote this.

Run: python tests/test_precision_ghost_power_benchmark.py
"""

import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scripts.precision_ghost_power_benchmark import (
    compute_flops,
    compute_cei,
    compute_ghost_share,
    check_hypothesis,
    get_dtype_and_matmul_fn,
    poll_power_w,
    MATMUL_DIM,
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


# ---------------------------------------------------------------------
# FLOPs / CEI math
# ---------------------------------------------------------------------

def test_compute_flops_matches_hand_calculation():
    flops = compute_flops(matmul_dim=100, iters=5)
    expected = 2 * (100 ** 3) * 5
    check("compute_flops matches hand calculation for a small case",
          flops == expected, f"got {flops}, expected {expected}")


def test_compute_cei_basic():
    # 1000 FLOPs total, 10W for 2s => 20J => 50 FLOPs/J
    cei = compute_cei(total_flops=1000, active_w=10, elapsed_s=2)
    check("compute_cei: basic case matches hand calculation",
          cei == 50.0, f"got {cei}")


def test_compute_cei_none_on_missing_power():
    check("compute_cei: returns None when active_w is None (not a "
          "silent 0 or crash)", compute_cei(1000, None, 2) is None)


def test_compute_cei_none_on_zero_power():
    check("compute_cei: returns None on zero power, not a division error",
          compute_cei(1000, 0, 2) is None)


def test_compute_cei_none_on_zero_elapsed():
    check("compute_cei: returns None on zero elapsed time",
          compute_cei(1000, 10, 0) is None)


# ---------------------------------------------------------------------
# Ghost share computation -- the actual hypothesis measurement
# ---------------------------------------------------------------------

def test_ghost_share_basic_calculation():
    """Bare idle 50W, context idle 90W (ghost=40W), active 200W ->
    ghost_share = 40/200*100 = 20%."""
    results = [{'precision': 'fp32', 'supported': True,
                'context_idle_w': 90, 'active_w': 200}]
    out = compute_ghost_share(results, bare_idle_w=50)
    check("ghost_share: basic hand-checked calculation",
          out[0]['ghost_power_w'] == 40 and out[0]['ghost_share_pct'] == 20.0,
          f"got {out[0]}")


def test_ghost_share_none_for_unsupported_precision():
    results = [{'precision': 'fp4', 'supported': False, 'reason': 'no lib'}]
    out = compute_ghost_share(results, bare_idle_w=50)
    check("ghost_share: None for an unsupported precision, not a crash "
          "or a fabricated number",
          out[0]['ghost_power_w'] is None and out[0]['ghost_share_pct'] is None,
          f"got {out[0]}")


def test_ghost_share_none_when_bare_idle_missing():
    results = [{'precision': 'fp32', 'supported': True,
                'context_idle_w': 90, 'active_w': 200}]
    out = compute_ghost_share(results, bare_idle_w=None)
    check("ghost_share: None when bare_idle_w measurement itself failed",
          out[0]['ghost_power_w'] is None, f"got {out[0]}")


def test_ghost_share_hypothesis_scenario_realistic():
    """The actual scenario the hypothesis predicts: ghost power roughly
    CONSTANT across precisions (~40W) while active power drops sharply
    as precision gets cheaper -> ghost_share should RISE as active_w
    falls."""
    results = [
        {'precision': 'fp32', 'supported': True, 'context_idle_w': 90, 'active_w': 600},
        {'precision': 'bf16', 'supported': True, 'context_idle_w': 92, 'active_w': 400},
        {'precision': 'fp8', 'supported': True, 'context_idle_w': 88, 'active_w': 250},
        {'precision': 'int8', 'supported': True, 'context_idle_w': 91, 'active_w': 150},
    ]
    out = compute_ghost_share(results, bare_idle_w=50)
    shares = {r['precision']: r['ghost_share_pct'] for r in out}
    check("ghost_share: in the hypothesis-consistent scenario, share is "
          "lowest at the most expensive precision (fp32) and highest at "
          "the cheapest (int8)",
          shares['fp32'] < shares['bf16'] < shares['fp8'] < shares['int8'],
          f"got {shares}")


# ---------------------------------------------------------------------
# Hypothesis check function -- must not overclaim
# ---------------------------------------------------------------------

def test_check_hypothesis_confirms_clean_monotonic_trend():
    results = [
        {'precision': 'fp32', 'active_w': 600, 'ghost_share_pct': 6.7},
        {'precision': 'bf16', 'active_w': 400, 'ghost_share_pct': 10.5},
        {'precision': 'int8', 'active_w': 150, 'ghost_share_pct': 27.3},
    ]
    confirmed, msg, sorted_results = check_hypothesis(results)
    check("check_hypothesis: confirms True on a clean monotonic trend",
          confirmed is True, f"got {confirmed}, msg={msg}")


def test_check_hypothesis_rejects_non_monotonic_data():
    """Real, honest measurement noise -- the trend is NOT clean. Must
    report False, not force a confirmation onto noisy data."""
    results = [
        {'precision': 'fp32', 'active_w': 600, 'ghost_share_pct': 15.0},
        {'precision': 'bf16', 'active_w': 400, 'ghost_share_pct': 8.0},  # goes down, breaks trend
        {'precision': 'int8', 'active_w': 150, 'ghost_share_pct': 27.0},
    ]
    confirmed, msg, sorted_results = check_hypothesis(results)
    check("check_hypothesis: correctly reports False (not confirmed) on "
          "non-monotonic data, does not force-fit a confirmation",
          confirmed is False, f"got {confirmed}, msg={msg}")


def test_check_hypothesis_returns_none_with_insufficient_data():
    """One data point -- there's no trend to check. Must be distinct
    from 'checked and found false', not conflated with it."""
    results = [{'precision': 'fp32', 'active_w': 600, 'ghost_share_pct': 15.0}]
    confirmed, msg, sorted_results = check_hypothesis(results)
    check("check_hypothesis: returns None (not False) when there isn't "
          "enough data to check at all -- 'unknown' and 'checked, not "
          "true' must not be the same value",
          confirmed is None, f"got {confirmed}")


def test_check_hypothesis_ignores_unsupported_entries():
    results = [
        {'precision': 'fp32', 'active_w': 600, 'ghost_share_pct': 10.0},
        {'precision': 'fp4', 'active_w': None, 'ghost_share_pct': None},  # unsupported
        {'precision': 'int8', 'active_w': 150, 'ghost_share_pct': 25.0},
    ]
    confirmed, msg, sorted_results = check_hypothesis(results)
    check("check_hypothesis: silently ignores unsupported/None entries "
          "rather than crashing on them",
          confirmed is True and len(sorted_results) == 2,
          f"got confirmed={confirmed}, n={len(sorted_results)}")


# ---------------------------------------------------------------------
# Precision selection logic -- proven without needing real CUDA
# ---------------------------------------------------------------------

def _fake_torch_full_support():
    """A fake torch module that claims to support everything, including
    fp8/int8, to test the SELECTION logic (not real GPU execution)."""
    m = MagicMock()
    m.cuda.is_available.return_value = True
    m.float8_e4m3fn = 'fake_fp8_dtype'
    m._scaled_mm = MagicMock()
    m._int_mm = MagicMock()
    return m


def _fake_torch_minimal_support():
    """A fake torch module lacking fp8/int8 support, simulating an older
    PyTorch version or non-FP8 hardware."""
    m = MagicMock(spec=['cuda', 'backends', 'randn', 'float32', 'bfloat16', 'float16'])
    m.cuda.is_available.return_value = True
    return m


def test_precision_selection_fp32_always_supported():
    _, _, _, supported = get_dtype_and_matmul_fn('fp32', torch_module=_fake_torch_minimal_support())
    check("precision selection: fp32 supported even on minimal torch",
          supported is True)


def test_precision_selection_bf16_always_supported():
    _, _, _, supported = get_dtype_and_matmul_fn('bf16', torch_module=_fake_torch_minimal_support())
    check("precision selection: bf16 supported even on minimal torch "
          "(it's a standard dtype, not a specialized library feature)",
          supported is True)


def test_precision_selection_fp8_unsupported_on_minimal_torch():
    _, _, _, supported = get_dtype_and_matmul_fn('fp8', torch_module=_fake_torch_minimal_support())
    check("precision selection: fp8 correctly reports UNSUPPORTED when "
          "the required attributes are missing, rather than crashing "
          "later mid-benchmark",
          supported is False)


def test_precision_selection_fp8_supported_when_available():
    _, _, _, supported = get_dtype_and_matmul_fn('fp8', torch_module=_fake_torch_full_support())
    check("precision selection: fp8 reports supported when the "
          "environment actually has the required attributes",
          supported is True)


def test_precision_selection_fp4_always_unsupported():
    """FP4 has no vanilla-PyTorch path at all -- must always report
    unsupported, even on a fully-featured fake torch, since the
    function correctly never implements a fake FP4 path."""
    _, _, _, supported = get_dtype_and_matmul_fn('fp4', torch_module=_fake_torch_full_support())
    check("precision selection: fp4 always reports unsupported (no "
          "vanilla PyTorch path exists for it)", supported is False)


def test_precision_selection_no_torch_all_unsupported():
    _, _, _, supported = get_dtype_and_matmul_fn('fp32', torch_module=None)
    check("precision selection: everything unsupported when torch "
          "itself is unavailable (None passed explicitly)",
          supported is False)


# ---------------------------------------------------------------------
# poll_power_w -- median-taking logic, with injected fake time/subprocess
# ---------------------------------------------------------------------

def test_poll_power_w_takes_median_not_mean():
    """One wild outlier must not skew the result -- same median-not-mean
    discipline as every baseline elsewhere in this codebase."""
    fake_clock = {'t': 0.0}
    def fake_time():
        return fake_clock['t']
    def fake_sleep(s):
        fake_clock['t'] += s

    call_n = {'n': 0}
    readings = [100.0, 101.0, 500.0, 99.0, 100.0]  # 500 is a wild outlier

    def fake_run(cmd, **kw):
        val = readings[call_n['n'] % len(readings)]
        call_n['n'] += 1
        class R:
            pass
        r = R()
        r.stdout = f"{val}\n"
        return r

    result = poll_power_w(duration_s=2.4, interval_s=0.5,
                           sleep_fn=fake_sleep, time_fn=fake_time, run_fn=fake_run)
    check("poll_power_w: median resists a single wild outlier reading",
          result is not None and result < 200, f"got {result}")


def test_poll_power_w_none_when_no_samples_collected():
    calls = {'n': 0}
    def fake_time():
        # First call establishes 'end' near 0; second call is already
        # past it, so the loop body never executes even once.
        calls['n'] += 1
        return 0 if calls['n'] == 1 else 999999
    result = poll_power_w(duration_s=5, time_fn=fake_time,
                           sleep_fn=lambda s: None, run_fn=lambda *a, **kw: None)
    check("poll_power_w: returns None (not a crash or a fabricated 0) "
          "when no samples were collected", result is None)


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
