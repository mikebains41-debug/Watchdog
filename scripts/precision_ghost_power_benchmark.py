#!/usr/bin/env python3
"""
scripts/precision_ghost_power_benchmark.py

Extends the ghost power finding across compute precisions. Previously
validated: FP32 (3.178e11 FLOPs/J), FP16 (2.846e12), FP8 (9.59e11) via
Serial Alice certificates. Never measured: BF16 -- the actual default
training precision for most LLMs today, wider dynamic range than FP16,
avoids the gradient overflow/underflow problems FP16 has at scale. Also
never measured: TF32 (NVIDIA's actual DEFAULT matmul precision on
Ampere+ unless explicitly disabled -- most real-world workloads run
here without the operator choosing it), and the newer FP4/microscaling
formats Blackwell (B200/B300) is built around.

THE HYPOTHESIS THIS TESTS, stated as something that can be wrong:
Ghost power is caused by the memory subsystem staying locked at full
clock speed, not by compute precision. If that's right, ghost power in
watts should stay roughly CONSTANT across precisions, while active
compute power drops sharply as precision gets cheaper (that's the whole
point of FP4). If true: ghost power's SHARE of total energy during
active compute GROWS as workloads move to cheaper precision -- meaning
the industry's own move toward efficient low-precision inference makes
this specific waste worse, not better. This script measures the real
numbers and reports whether the data shows that trend or not, without
assuming the answer either way.

STATUS: unexecuted. No GPU exists in the environment that wrote this.
The measurement LOGIC (FLOPs math, ghost-share computation, hypothesis
check) is unit-tested against synthetic data -- see
tests/test_precision_ghost_power_benchmark.py. That proves the
arithmetic is correct. It proves nothing about what real hardware
actually does. That requires running this script for real.

Requires: torch with CUDA support, nvidia-smi.

Usage:
  python3 scripts/precision_ghost_power_benchmark.py
  python3 scripts/precision_ghost_power_benchmark.py --precisions fp32 bf16 fp16
  python3 scripts/precision_ghost_power_benchmark.py --idle-window 30 --active-window 30
"""

import argparse
import json
import subprocess
import time
import sys
import os
from datetime import datetime

try:
    import torch
except ImportError:
    torch = None


PRECISIONS = ['fp32', 'tf32', 'bf16', 'fp16', 'fp8', 'int8', 'fp4']

# Matrix dimension for the sustained matmul workload. 8192x8192 keeps
# VRAM usage modest (~537MB for a pair of fp32 tensors) while giving a
# large enough compute window to measure power against, on any modern
# datacenter GPU (H100/H200/B200/B300, and 40GB+ A100).
MATMUL_DIM = 8192


def poll_power_w(gpu_index=0, duration_s=10, interval_s=0.5, sleep_fn=time.sleep,
                  time_fn=time.time, run_fn=subprocess.run):
    """
    Polls nvidia-smi power.draw for duration_s, returns the MEDIAN --
    matching every baseline elsewhere in this codebase (GhostPowerDetector,
    etc.), since a single contaminated sample shouldn't skew a value used
    for comparison. sleep_fn/time_fn/run_fn are injectable for testing
    without real hardware or real wall-clock waits.
    """
    samples = []
    end = time_fn() + duration_s
    while time_fn() < end:
        try:
            r = run_fn(
                ['nvidia-smi', '--query-gpu=power.draw', '--format=csv,noheader,nounits',
                 f'--id={gpu_index}'],
                capture_output=True, text=True, timeout=5)
            val = r.stdout.strip().split('\n')[0].strip()
            samples.append(float(val))
        except Exception:
            pass
        sleep_fn(interval_s)
    if not samples:
        return None
    samples.sort()
    return samples[len(samples) // 2]


def compute_flops(matmul_dim, iters):
    """2*M*K*N per matmul (multiply+add counted as 2 FLOPs each) -- the
    standard convention for GEMM FLOPs accounting. Square matrices here,
    so M=K=N=matmul_dim."""
    return 2 * (matmul_dim ** 3) * iters


def compute_cei(total_flops, active_w, elapsed_s):
    """FLOPs per joule. None if power/time data is missing or non-positive
    -- never silently returns 0 or a divide-by-zero result."""
    if not active_w or active_w <= 0 or not elapsed_s or elapsed_s <= 0:
        return None
    energy_j = active_w * elapsed_s
    return total_flops / energy_j


def compute_ghost_share(results, bare_idle_w):
    """
    THE hypothesis test, computed per precision:

    ghost_power_w = context_idle_w - bare_idle_w
      (elevation above TRUE idle caused by the resident CUDA context and
      locked memory clock -- isolated from whatever this precision's
      tensors happen to be, since bare_idle_w is measured once, before
      any context exists)

    ghost_share_pct = ghost_power_w / active_w * 100
      (what fraction of TOTAL power during active compute is just the
      ghost floor, not actual work -- this is the number that matters)

    Mutates and returns the same list of result dicts, adding
    ghost_power_w and ghost_share_pct (or None if the underlying
    measurements are missing/unsupported).
    """
    for r in results:
        if (not r.get('supported') or r.get('context_idle_w') is None
                or r.get('active_w') is None or bare_idle_w is None):
            r['ghost_power_w'] = None
            r['ghost_share_pct'] = None
            continue
        ghost_w = r['context_idle_w'] - bare_idle_w
        r['ghost_power_w'] = ghost_w
        r['ghost_share_pct'] = (ghost_w / r['active_w'] * 100) if r['active_w'] > 0 else None
    return results


def check_hypothesis(supported_results):
    """
    Sorts supported results by active power (ascending -- cheapest
    compute first) and checks whether ghost_share_pct is monotonically
    DEcreasing as active power INcreases (equivalently: monotonically
    INcreasing as precision gets cheaper).

    Returns (confirmed: bool or None, message: str, sorted_results: list).
    confirmed=None means there wasn't enough data to check at all --
    that is reported as its own outcome, not folded into False, since
    "we don't know" and "we checked and it's not true" are different
    findings and this must not blur them together.
    """
    usable = [r for r in supported_results
              if r.get('ghost_share_pct') is not None and r.get('active_w') is not None]
    if len(usable) < 2:
        return None, "Not enough supported precisions with valid measurements to check the trend.", usable

    sorted_by_active = sorted(usable, key=lambda r: r['active_w'])
    shares = [r['ghost_share_pct'] for r in sorted_by_active]
    monotonic_nonincreasing = all(shares[i] >= shares[i + 1] for i in range(len(shares) - 1))
    strictly_different = shares[0] > shares[-1]

    if monotonic_nonincreasing and strictly_different:
        msg = ("CONFIRMED PATTERN: ghost power's share of total power is "
               "HIGHEST at the cheapest-compute precision and LOWEST at "
               "the most expensive-compute precision -- consistent with "
               "the hypothesis that cheaper precision makes ghost power a "
               "BIGGER problem, not a smaller one.")
        return True, msg, sorted_by_active

    msg = ("NOT CONFIRMED: the data does not show a clean monotonic trend "
           "in this run. Report the actual numbers, not the hypothesis -- "
           "this could mean the hypothesis is wrong, or that measurement "
           "noise/sample size is obscuring a real trend. Do not claim "
           "confirmation either way from a single run.")
    return False, msg, sorted_by_active


def get_dtype_and_matmul_fn(precision, torch_module=None):
    """
    Returns (setup_fn, matmul_fn, teardown_fn, supported) for a given
    precision string. Precisions requiring libraries not guaranteed
    present (FP8, FP4, INT8 GEMM) are attempted and reported UNSUPPORTED
    cleanly if unavailable, rather than crashing the whole benchmark run
    or silently substituting a different precision.

    torch_module is injectable so this function's SELECTION logic (which
    branch fires for which precision string) can be unit tested without
    a real torch/CUDA environment.
    """
    t = torch_module if torch_module is not None else torch
    if t is None or not getattr(t.cuda, 'is_available', lambda: False)():
        return None, None, None, False

    device = 'cuda'

    if precision == 'fp32':
        def setup():
            t.backends.cuda.matmul.allow_tf32 = False
            a = t.randn(MATMUL_DIM, MATMUL_DIM, dtype=t.float32, device=device)
            b = t.randn(MATMUL_DIM, MATMUL_DIM, dtype=t.float32, device=device)
            return a, b
        def mm(a, b): return a @ b
        def teardown(): pass
        return setup, mm, teardown, True

    if precision == 'tf32':
        # Not a distinct dtype -- FP32 tensors, matmul computed
        # internally at reduced (TF32) precision. This is NVIDIA's
        # actual default on Ampere+ unless explicitly disabled, so it's
        # the realistic "most workloads run this" case, not an edge case.
        def setup():
            t.backends.cuda.matmul.allow_tf32 = True
            a = t.randn(MATMUL_DIM, MATMUL_DIM, dtype=t.float32, device=device)
            b = t.randn(MATMUL_DIM, MATMUL_DIM, dtype=t.float32, device=device)
            return a, b
        def mm(a, b): return a @ b
        def teardown(): t.backends.cuda.matmul.allow_tf32 = False
        return setup, mm, teardown, True

    if precision == 'bf16':
        def setup():
            a = t.randn(MATMUL_DIM, MATMUL_DIM, dtype=t.bfloat16, device=device)
            b = t.randn(MATMUL_DIM, MATMUL_DIM, dtype=t.bfloat16, device=device)
            return a, b
        def mm(a, b): return a @ b
        def teardown(): pass
        return setup, mm, teardown, True

    if precision == 'fp16':
        def setup():
            a = t.randn(MATMUL_DIM, MATMUL_DIM, dtype=t.float16, device=device)
            b = t.randn(MATMUL_DIM, MATMUL_DIM, dtype=t.float16, device=device)
            return a, b
        def mm(a, b): return a @ b
        def teardown(): pass
        return setup, mm, teardown, True

    if precision == 'fp8':
        # Requires torch>=2.1 float8 dtypes AND native FP8 hardware
        # support (Hopper/Blackwell). Older PyTorch or non-FP8 hardware
        # correctly reports unsupported here.
        if not hasattr(t, 'float8_e4m3fn') or not hasattr(t, '_scaled_mm'):
            return None, None, None, False
        def setup():
            a = t.randn(MATMUL_DIM, MATMUL_DIM, dtype=t.float32, device=device).to(t.float8_e4m3fn)
            b = t.randn(MATMUL_DIM, MATMUL_DIM, dtype=t.float32, device=device).to(t.float8_e4m3fn)
            return a, b
        def mm(a, b): return t._scaled_mm(a, b, out_dtype=t.bfloat16)
        def teardown(): pass
        return setup, mm, teardown, True

    if precision == 'int8':
        if not hasattr(t, '_int_mm'):
            return None, None, None, False
        def setup():
            a = (t.randn(MATMUL_DIM, MATMUL_DIM, device=device) * 127).to(t.int8)
            b = (t.randn(MATMUL_DIM, MATMUL_DIM, device=device) * 127).to(t.int8)
            return a, b
        def mm(a, b): return t._int_mm(a, b)
        def teardown(): pass
        return setup, mm, teardown, True

    if precision == 'fp4':
        # FP4 / microscaling formats need transformer_engine or an
        # equivalent Blackwell-specific library, not present in vanilla
        # PyTorch as of this writing. Always reports unsupported here
        # rather than silently skipping without explanation -- the
        # caller is responsible for logging WHY.
        return None, None, None, False

    return None, None, None, False


def run_precision_benchmark(precision, gpu_index=0, idle_window_s=15,
                             active_window_s=15, warmup_iters=10,
                             torch_module=None):
    """
    Full measurement for ONE precision. Returns a result dict, always
    including 'precision' and 'supported'.
    """
    t = torch_module if torch_module is not None else torch
    setup, mm, teardown, supported = get_dtype_and_matmul_fn(precision, torch_module=t)
    if not supported:
        return {'precision': precision, 'supported': False,
                'reason': 'dtype/library not available in this environment'}

    result = {'precision': precision, 'supported': True}
    try:
        a, b = setup()
        t.cuda.synchronize()

        print(f"[{precision}] Context created. Measuring idle-with-context "
              f"power for {idle_window_s}s (GPU should show 0% util)...")
        result['context_idle_w'] = poll_power_w(gpu_index, duration_s=idle_window_s)

        print(f"[{precision}] Warming up ({warmup_iters} iterations)...")
        for _ in range(warmup_iters):
            _ = mm(a, b)
        t.cuda.synchronize()

        print(f"[{precision}] Measuring active compute power + real "
              f"achieved FLOPs for {active_window_s}s...")
        iters = 0
        start = time.perf_counter()
        power_samples = []
        end_time = time.time() + active_window_s
        next_poll = time.time()
        while time.time() < end_time:
            _ = mm(a, b)
            iters += 1
            if time.time() >= next_poll:
                try:
                    r = subprocess.run(
                        ['nvidia-smi', '--query-gpu=power.draw',
                         '--format=csv,noheader,nounits', f'--id={gpu_index}'],
                        capture_output=True, text=True, timeout=5)
                    power_samples.append(float(r.stdout.strip().split('\n')[0]))
                except Exception:
                    pass
                next_poll = time.time() + 0.5
        t.cuda.synchronize()
        elapsed = time.perf_counter() - start

        power_samples.sort()
        active_w = power_samples[len(power_samples) // 2] if power_samples else None
        result['active_w'] = active_w
        result['iters'] = iters
        result['elapsed_s'] = elapsed

        total_flops = compute_flops(MATMUL_DIM, iters)
        result['total_flops'] = total_flops
        result['achieved_flops_per_s'] = total_flops / elapsed if elapsed > 0 else None
        result['cei_flops_per_joule'] = compute_cei(total_flops, active_w, elapsed)

        teardown()
        del a, b
        t.cuda.empty_cache()

    except Exception as e:
        result['supported'] = False
        result['reason'] = f'runtime error: {e!r}'

    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--gpu', type=int, default=0)
    parser.add_argument('--precisions', nargs='+', default=PRECISIONS,
                         help=f"Which precisions to test. Default: all of {PRECISIONS}")
    parser.add_argument('--idle-window', type=int, default=15)
    parser.add_argument('--active-window', type=int, default=15)
    parser.add_argument('--bare-idle-window', type=int, default=30)
    parser.add_argument('--output', type=str, default=None)
    args = parser.parse_args()

    if torch is None:
        print("[ABORT] torch is not installed in this environment.")
        sys.exit(1)
    if not torch.cuda.is_available():
        print("[ABORT] torch.cuda.is_available() is False -- no GPU visible to torch.")
        sys.exit(1)

    print("=" * 70)
    print("PRECISION GHOST POWER BENCHMARK")
    print("=" * 70)
    print(f"GPU: {torch.cuda.get_device_name(args.gpu)}")
    print(f"Testing precisions: {args.precisions}")
    print()
    print("[STEP 0] Measuring TRUE bare-idle power (no CUDA context from "
          f"this process) for {args.bare_idle_window}s. Make sure nothing "
          "else is about to start on this GPU.")
    bare_idle_w = poll_power_w(args.gpu, duration_s=args.bare_idle_window)
    print(f"  Bare idle floor: {bare_idle_w}W")

    results = []
    for precision in args.precisions:
        print(f"\n--- {precision.upper()} ---")
        r = run_precision_benchmark(precision, gpu_index=args.gpu,
                                     idle_window_s=args.idle_window,
                                     active_window_s=args.active_window)
        if not r.get('supported'):
            print(f"[SKIP] {precision}: {r.get('reason')}")
        else:
            cei = r.get('cei_flops_per_joule')
            print(f"  context_idle_w={r.get('context_idle_w')}  "
                  f"active_w={r.get('active_w')}  "
                  f"CEI={cei:.3e} FLOPs/J" if cei else "  CEI=N/A")
        results.append(r)

    results = compute_ghost_share(results, bare_idle_w)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"{'Precision':<10}{'Ctx Idle W':<12}{'Active W':<12}{'CEI (FLOPs/J)':<16}{'Ghost W':<10}{'Ghost %':<10}")
    for r in results:
        if not r.get('supported'):
            print(f"{r['precision']:<10}{'UNSUPPORTED':<12}")
            continue
        cei = f"{r['cei_flops_per_joule']:.2e}" if r.get('cei_flops_per_joule') else "N/A"
        gw = f"{r['ghost_power_w']:.1f}" if r.get('ghost_power_w') is not None else "N/A"
        gp = f"{r['ghost_share_pct']:.1f}%" if r.get('ghost_share_pct') is not None else "N/A"
        print(f"{r['precision']:<10}{str(r.get('context_idle_w')):<12}{str(r.get('active_w')):<12}{cei:<16}{gw:<10}{gp:<10}")

    print("\n" + "=" * 70)
    print("HYPOTHESIS CHECK: does ghost power's SHARE of total power rise")
    print("as precision gets cheaper (lower active power draw)?")
    print("=" * 70)
    confirmed, msg, sorted_results = check_hypothesis(results)
    for r in sorted_results:
        print(f"  {r['precision']:<8} active={r['active_w']:.1f}W  "
              f"ghost_share={r['ghost_share_pct']:.1f}%")
    print()
    print(msg)

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_path = args.output or f'precision_benchmark_{ts}.json'
    with open(output_path, 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'gpu': torch.cuda.get_device_name(args.gpu),
            'bare_idle_w': bare_idle_w,
            'hypothesis_confirmed': confirmed,
            'results': results,
        }, f, indent=2)
    print(f"\nFull results written to {output_path}")


if __name__ == '__main__':
    main()
