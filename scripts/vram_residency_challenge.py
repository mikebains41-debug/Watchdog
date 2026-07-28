#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
scripts/vram_residency_challenge.py

Active VRAM residency verification, COMPLEMENTING (not replacing)
VRAMResidualDetector's passive compute_apps-based approach in
detection/engines.py.

Based on the Challenge-Response primitive in "Timing and Memory
Telemetry on GPUs for AI Governance" (Monfared, Ganji, Holcomb, Tajik --
WPI/UMass Amherst, arXiv 2602.09369): store a known challenge dataset in
GPU VRAM, then periodically re-read it and measure access latency. Their
own measured numbers on H100: >350ms latency gap between hot
(HBM-resident) and cold (evicted to host RAM) access, negligible power
overhead, negligible throughput cost -- cheaper than their other three
primitives (PoW, VDF, GEMM), which all impose continuous compute load.

WHY THIS COMPLEMENTS THE EXISTING PASSIVE APPROACH:
VRAMResidualDetector waits for a PID to disappear from compute_apps,
then checks whether its memory was reclaimed -- inherently REACTIVE, it
only evaluates after an exit has already happened. This script actively
verifies memory residency at any moment, independent of process
lifecycle events -- catching cases the passive approach structurally
cannot, e.g. confirming memory hasn't been silently evicted or swapped
BEFORE any exit occurs.

HONEST SIMPLIFICATIONS vs. the source paper, stated rather than hidden:
  - The paper uses a keyed Argon2id hash (memory-hard, resistant to
    precomputation/replay) for the actual residency probe. Implementing
    a correct, secure Argon2id CUDA kernel is a substantial additional
    dependency. This script uses a simple sum-reduction pass instead --
    it still forces a full memory traversal, which is the property the
    residency signal actually depends on, but it is far easier to game
    or precompute than a real keyed hash. Treat this as a first-pass
    approximation of their construction, not a reproduction of it.
  - The paper calibrates BOTH a real "hot" baseline AND a real "cold"
    baseline (by explicitly forcing placement in pinned host memory) to
    set classification thresholds. This script only calibrates the hot
    side on your real GPU and ASSUMES a cold threshold (5x the hot
    median, floor of +50ms) rather than measuring a real cold access --
    forcing genuinely cold placement needs pinned-host-memory plumbing
    beyond this first-pass version. This is a real, disclosed asymmetry,
    not a hidden one.

STATUS: unexecuted. No GPU exists in the environment that wrote this.
The measurement LOGIC (latency classification, threshold math) is
unit-tested against synthetic data -- see
tests/test_vram_residency_challenge.py. That proves the arithmetic is
correct. It proves nothing about what real hardware actually measures.

Requires: torch with CUDA support.

Usage:
  python3 scripts/vram_residency_challenge.py
  python3 scripts/vram_residency_challenge.py --challenge-mb 1024 --rounds 30
"""

import argparse
import json
import time
import sys
from datetime import datetime

try:
    import torch
except ImportError:
    torch = None


# Default challenge size. The source paper used up to 60GB on H100;
# this defaults far smaller since Watchdog aims to run alongside a real
# workload's own VRAM usage, not compete with it for space.
DEFAULT_CHALLENGE_MB = 512


def classify_residency(latency_ms, hot_threshold_ms, cold_threshold_ms):
    """
    Classifies a measured access latency as 'hot' (resident in HBM),
    'cold' (likely evicted), or 'ambiguous' (between the two calibrated
    thresholds -- reported honestly rather than forced into a binary
    answer). hot_threshold_ms and cold_threshold_ms must come from real
    calibration on the target GPU (see calibrate_thresholds) -- the
    source paper's own >350ms gap was measured on their specific
    hardware/dataset-size combination and is not assumed to transfer
    unchanged to different hardware or challenge sizes.
    """
    if latency_ms <= hot_threshold_ms:
        return 'hot'
    if latency_ms >= cold_threshold_ms:
        return 'cold'
    return 'ambiguous'


def compute_cold_threshold(hot_median_ms, multiplier=5.0, min_gap_ms=50.0):
    """
    Derives an assumed cold threshold from a real measured hot median,
    since this script cannot force genuinely cold placement to
    calibrate against directly (see module docstring's disclosed
    asymmetry). Always at least min_gap_ms above the hot median, even
    when the hot median itself is very small (e.g. sub-millisecond),
    to avoid a threshold that's trivially crossed by ordinary jitter.
    """
    return max(hot_median_ms * multiplier, hot_median_ms + min_gap_ms)


def median(values):
    """Plain median, no external dependency, used for calibration."""
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 0:
        return (s[mid - 1] + s[mid]) / 2
    return s[mid]


def run_challenge(challenge_mb=DEFAULT_CHALLENGE_MB, device_index=0,
                   torch_module=None):
    """
    Allocates a challenge tensor in VRAM, forces a full bandwidth-bound
    read over it (sum reduction -- see module docstring's honest
    simplification note), and measures wall-clock access latency.

    Returns (latency_ms, challenge_mb) or (None, None) if no CUDA GPU
    is visible to torch.
    """
    t = torch_module if torch_module is not None else torch
    if t is None or not t.cuda.is_available():
        return None, None

    device = f'cuda:{device_index}'
    n_elements = int(challenge_mb * 1024 * 1024 / 4)  # float32 = 4 bytes
    chal = t.randn(n_elements, dtype=t.float32, device=device)
    t.cuda.synchronize()

    start = time.perf_counter()
    _ = chal.sum().item()  # forces a full read; .item() forces host sync
    t.cuda.synchronize()
    elapsed_ms = (time.perf_counter() - start) * 1000

    del chal
    t.cuda.empty_cache()
    return elapsed_ms, challenge_mb


def calibrate_thresholds(challenge_mb=DEFAULT_CHALLENGE_MB, device_index=0,
                          samples=10, torch_module=None):
    """
    Measures several hot-access latencies on THIS real GPU to establish
    a real baseline, rather than assuming the source paper's numbers
    transfer unchanged. Returns (hot_threshold_ms, cold_threshold_ms).
    Returns (None, None) if no samples could be collected (e.g. no
    CUDA GPU visible).
    """
    latencies = []
    for _ in range(samples):
        lat, _ = run_challenge(challenge_mb, device_index, torch_module=torch_module)
        if lat is not None:
            latencies.append(lat)
    if not latencies:
        return None, None
    hot_median = median(latencies)
    cold_threshold = compute_cold_threshold(hot_median)
    return hot_median, cold_threshold


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--gpu', type=int, default=0)
    parser.add_argument('--challenge-mb', type=int, default=DEFAULT_CHALLENGE_MB)
    parser.add_argument('--rounds', type=int, default=20)
    parser.add_argument('--interval-s', type=float, default=5.0)
    parser.add_argument('--output', type=str, default=None)
    args = parser.parse_args()

    if torch is None:
        print("[ABORT] torch is not installed in this environment.")
        sys.exit(1)
    if not torch.cuda.is_available():
        print("[ABORT] torch.cuda.is_available() is False -- no GPU visible to torch.")
        sys.exit(1)

    print("=" * 70)
    print("ACTIVE VRAM RESIDENCY CHALLENGE-RESPONSE")
    print("=" * 70)
    print(f"GPU: {torch.cuda.get_device_name(args.gpu)}")
    print(f"[STEP 0] Calibrating hot-access baseline on THIS GPU "
          f"({args.challenge_mb}MB challenge, 10 samples)...")
    hot_threshold, cold_threshold = calibrate_thresholds(args.challenge_mb, args.gpu)
    if hot_threshold is None:
        print("[ABORT] Calibration failed -- no samples collected.")
        sys.exit(1)
    print(f"  Hot baseline: {hot_threshold:.2f}ms")
    print(f"  Cold threshold (ASSUMED from hot baseline, not measured -- "
          f"see script docstring's disclosed asymmetry): {cold_threshold:.2f}ms")

    results = []
    print(f"\n[STEP 1] Running {args.rounds} challenge rounds, "
          f"{args.interval_s}s apart...")
    for i in range(args.rounds):
        latency, _ = run_challenge(args.challenge_mb, args.gpu)
        classification = classify_residency(latency, hot_threshold, cold_threshold)
        print(f"  Round {i+1}/{args.rounds}: {latency:.2f}ms -> {classification}")
        results.append({'round': i + 1, 'latency_ms': latency,
                         'classification': classification,
                         'timestamp': datetime.now().isoformat()})
        if i < args.rounds - 1:
            time.sleep(args.interval_s)

    non_hot_count = sum(1 for r in results if r['classification'] != 'hot')
    print(f"\n{'='*70}\nSUMMARY\n{'='*70}")
    print(f"{non_hot_count}/{len(results)} rounds classified non-hot "
          f"(cold or ambiguous)")
    if non_hot_count > 0:
        print("Non-hot classifications mean the challenge dataset was NOT "
              "reliably resident in HBM for the full measurement window -- "
              "worth investigating whether something evicted it.")
    else:
        print("Challenge dataset remained HBM-resident for the entire "
              "measurement window.")

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_path = args.output or f'vram_residency_{ts}.json'
    with open(output_path, 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'gpu': torch.cuda.get_device_name(args.gpu),
            'challenge_mb': args.challenge_mb,
            'hot_threshold_ms': hot_threshold,
            'cold_threshold_ms': cold_threshold,
            'results': results,
        }, f, indent=2)
    print(f"\nFull results written to {output_path}")


if __name__ == '__main__':
    main()
