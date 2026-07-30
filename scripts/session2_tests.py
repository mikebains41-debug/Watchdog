#!/usr/bin/env python3
"""
scripts/session2_tests.py -- Watchdog

Runnable scripts for NEXT_SESSION_CHECKLIST.md. Each function corresponds
to one checklist item and prints raw numbers, not verdicts -- nothing
here overclaims a pass or fail. Run from the repo root:

    python3 scripts/session2_tests.py <test_name> [--gpu N]

Available tests:
    nvlink_retest          -- A1: NVLink detector retest against the rate fix
    sequential_read         -- B1: SequentialVRAMReadDetector, pinned-memory attempt
    covert_mining            -- B2: heavier/longer sustained-load retry
    handoff                  -- B3: bursts sized to the REAL achieved sample rate
    multigpu_correlation      -- B6: correlated burst DATA GENERATION ONLY
    reproducibility           -- C1+C2: CEI benchmark and residency probe, N repeats
    sustained_contention     -- C3: long-duration contention, not a short burst
    throttle_stress           -- E2: sustained heavy load while watching throttle flags

NOT included, and why:
    B4 (PowerLimitTamperDetector) -- two nvidia-smi commands, not worth a
        script. See NEXT_SESSION_CHECKLIST.md for the exact commands.
    B5 (PStateHonestyDetector) -- its real trigger condition has never been
        read in this project. Read detection/*.py for the class BEFORE
        writing any test for it. Do not guess at the condition -- that is
        exactly the mistake that produced the original NVLink counter bug.
"""

import sys
import os
import time
import json
import argparse
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def _now_iso():
    return datetime.now().isoformat()


def _launch_collector(gpu, duration_s, out_prefix):
    import subprocess
    log_path = out_prefix + ".log"
    jsonl_path = out_prefix + ".jsonl"
    proc = subprocess.Popen(
        ["python3", "watchdog.py", "--gpu", str(gpu), "--duration", str(duration_s),
         "--output", jsonl_path],
        stdout=open(log_path, "w"), stderr=subprocess.STDOUT,
    )
    return proc, log_path, jsonl_path


def cmd_nvlink_retest(args):
    """
    A1: Confirms NVLinkContentionDetector against the rate-based fix.
    Launches watchdog.py live, waits for a clean baseline, induces a
    real cross-GPU transfer. Read nvlink_total_kbs in the printed alert
    yourself -- sane (tens to low thousands of KB/s) or the old bug
    (billions/trillions)?
    """
    import torch

    baseline_s, transfer_s, buffer_s = 45, 90, 20
    total_s = baseline_s + transfer_s + buffer_s
    out_prefix = f"b200_watchdog/nvlink_retest_{int(time.time())}"

    print(f"[nvlink_retest] Launching watchdog.py for {total_s}s, output prefix={out_prefix}")
    proc, log_path, jsonl_path = _launch_collector(args.gpu, total_s, out_prefix)

    print(f"[nvlink_retest] Waiting {baseline_s}s for a clean idle baseline...")
    time.sleep(baseline_s)

    print(f"[nvlink_retest] Inducing real cross-GPU transfer for {transfer_s}s...")
    a = torch.randn(9000, 9000, device=f"cuda:{args.gpu}")
    other = 1 if args.gpu == 0 else 0
    end = time.time() + transfer_s
    while time.time() < end:
        _ = a.to(f"cuda:{other}")
        torch.cuda.synchronize()
    print("[nvlink_retest] Transfer done. Waiting for watchdog.py to finish...")

    proc.wait(timeout=total_s + 60)

    with open(log_path) as f:
        log_text = f.read()
    if "NVLINK_CONTENTION" in log_text:
        idx = log_text.find("NVLINK_CONTENTION")
        print("[nvlink_retest] FIRED -- inspect this block manually:")
        print(log_text[max(0, idx - 200):idx + 600])
    else:
        print("[nvlink_retest] Did NOT fire. Could mean the fix over-corrected, "
              "or delta_threshold_kbs needs tuning -- check the raw CSV for the "
              "real idle-vs-active rate gap before concluding anything.")
    print(f"[nvlink_retest] Full log: {log_path}")


def cmd_sequential_read(args):
    """
    B1: Attempt at a genuinely kernel-free memory read to trigger
    SequentialVRAMReadDetector (coverage_threshold_pct=30.0,
    util_mem_threshold=60.0, util_gpu_ceiling=5.0). Both prior attempts
    (.sum(), same-device .copy_()) dispatched a compute kernel and kept
    utilization.gpu at 90%+. This tries a pinned-memory host<->device
    transfer, which should use a DMA copy engine rather than an SM
    kernel -- but this is genuinely UNVERIFIED. Check the real
    utilization.gpu column in the CSV afterward; do not assume success.
    """
    import torch

    duration_s = 40
    out_prefix = f"b200_watchdog/sequential_read_retest_{int(time.time())}"
    proc, log_path, jsonl_path = _launch_collector(args.gpu, duration_s, out_prefix)
    time.sleep(3)

    print("[sequential_read] Running pinned-memory host<->device transfer loop...")
    device_t = torch.randn(20000, 20000, device=f"cuda:{args.gpu}")
    pinned = torch.empty_like(device_t, device="cpu").pin_memory()
    end = time.time() + 30
    while time.time() < end:
        pinned.copy_(device_t, non_blocking=True)
        torch.cuda.synchronize()
    print("[sequential_read] Transfer loop done.")

    proc.wait(timeout=duration_s + 60)
    print(f"[sequential_read] Check {jsonl_path}/*.csv columns utilization.gpu "
          f"and utilization.memory for the real result -- util.gpu should be "
          f"<=5% for this to be a valid test of this detector.")
    print(f"[sequential_read] Full log: {log_path}")


def cmd_covert_mining(args):
    """
    B2: Heavier/longer sustained load to clearly clear (or clearly
    miss) CovertMiningDetector's util_floor_pct=95.0,
    tdp_ceiling_fraction=0.90. Previous attempt landed at 89.7% of TDP
    -- a boundary case. Runs longer (200s) with a larger matmul.
    """
    import torch

    load_s = 200
    duration_s = load_s + 20
    out_prefix = f"b200_watchdog/covert_mining_retest_{int(time.time())}"
    proc, log_path, jsonl_path = _launch_collector(args.gpu, duration_s, out_prefix)
    time.sleep(3)

    print(f"[covert_mining] Running {load_s}s sustained heavy matmul...")
    a = torch.randn(10000, 10000, device=f"cuda:{args.gpu}")
    b = torch.randn(10000, 10000, device=f"cuda:{args.gpu}")
    end = time.time() + load_s
    while time.time() < end:
        _ = a @ b
        torch.cuda.synchronize()
    print("[covert_mining] Sustained load done.")

    proc.wait(timeout=duration_s + 60)
    with open(log_path) as f:
        log_text = f.read()
    if "COVERT_MINING_PATTERN" in log_text:
        print("[covert_mining] FIRED this time.")
    else:
        print("[covert_mining] Still did not fire -- check the real achieved "
              "power/TDP fraction in the CSV; if still under 90%, that's a "
              "real finding about the threshold, not a failed test.")
    print(f"[covert_mining] Full log: {log_path}")


def cmd_handoff(args):
    """
    B3: First probes the REAL achieved sample rate on this pod, then
    sizes idle/active bursts to match it, instead of assuming 100Hz.
    Previous attempt used 3.2s bursts against an actual ~3-7Hz rate and
    mostly missed them.
    """
    import torch

    print("[handoff] Probing real achieved sample rate first (15s)...")
    probe_prefix = f"b200_watchdog/handoff_rate_probe_{int(time.time())}"
    probe_proc, probe_log, _ = _launch_collector(args.gpu, 15, probe_prefix)
    probe_proc.wait(timeout=45)

    with open(probe_log) as f:
        probe_text = f.read()
    hz = 5.0  # sane fallback if parsing fails
    for line in probe_text.splitlines():
        if "achieved rate" in line:
            try:
                hz = float(line.split("achieved rate:")[1].split("Hz")[0].strip())
            except (IndexError, ValueError):
                pass
    burst_s = max(2.0, (1.0 / hz) * 6)  # aim for ~6 real samples per burst
    print(f"[handoff] Measured achieved rate: {hz:.2f}Hz -> using {burst_s:.1f}s bursts")

    n_cycles = 15
    total_active_s = 3 + n_cycles * 2 * burst_s + burst_s + burst_s * 3
    duration_s = int(total_active_s) + 30
    out_prefix = f"b200_watchdog/handoff_retest_{int(time.time())}"
    proc, log_path, jsonl_path = _launch_collector(args.gpu, duration_s, out_prefix)
    time.sleep(3)

    small_a = torch.randn(2500, 2500, device=f"cuda:{args.gpu}")
    small_b = torch.randn(2500, 2500, device=f"cuda:{args.gpu}")
    big_a = torch.randn(9000, 9000, device=f"cuda:{args.gpu}")
    big_b = torch.randn(9000, 9000, device=f"cuda:{args.gpu}")

    print(f"[handoff] Running {n_cycles} idle<->active cycles at {burst_s:.1f}s each...")
    for _ in range(n_cycles):
        end = time.time() + burst_s
        while time.time() < end:
            _ = small_a @ small_b
            torch.cuda.synchronize()
        time.sleep(burst_s)

    print("[handoff] Baseline cycles done. Running anomalous resume spike...")
    time.sleep(burst_s)
    end = time.time() + burst_s * 3
    while time.time() < end:
        _ = big_a @ big_b
        torch.cuda.synchronize()

    proc.wait(timeout=duration_s + 60)
    with open(log_path) as f:
        log_text = f.read()
    if "INTER_AGENT_HANDOFF_ANOMALY" in log_text:
        print("[handoff] FIRED this time.")
    else:
        print("[handoff] Still did not fire -- check the CSV's utilization.gpu "
              "column directly for 0% vs non-zero values during the burst "
              "windows before concluding anything.")
    print(f"[handoff] Full log: {log_path}")


def cmd_multigpu_correlation(args):
    """
    B6: DATA GENERATION ONLY. This project has never read
    MultiGPUCorrelation's actual trigger logic, so this does NOT claim
    to test it correctly -- it only produces a real correlated workload
    on both GPUs simultaneously. Read the class first:

        grep -n "class MultiGPUCorrelation" -A 40 detection/*.py

    ...then decide whether this data matches what it looks for before
    treating any fire/no-fire result as meaningful.
    """
    import torch
    import threading

    print("[multigpu_correlation] READ THE DETECTOR CLASS FIRST -- this script "
          "only generates correlated load, it does not know the real trigger "
          "condition. See this function's docstring.")

    load_s = 60
    duration_s = load_s + 15
    out_prefix = f"b200_watchdog/multigpu_correlation_data_{int(time.time())}"
    proc, log_path, jsonl_path = _launch_collector(0, duration_s, out_prefix)
    time.sleep(5)

    def burst(gpu_index):
        a = torch.randn(8000, 8000, device=f"cuda:{gpu_index}")
        b = torch.randn(8000, 8000, device=f"cuda:{gpu_index}")
        end = time.time() + load_s
        while time.time() < end:
            _ = a @ b
            torch.cuda.synchronize()

    print(f"[multigpu_correlation] Running correlated bursts on GPU0 and GPU1 "
          f"simultaneously for {load_s}s...")
    t0 = threading.Thread(target=burst, args=(0,))
    t1 = threading.Thread(target=burst, args=(1,))
    t0.start(); t1.start()
    t0.join(); t1.join()

    proc.wait(timeout=duration_s + 60)
    print(f"[multigpu_correlation] Data collection done. Log: {log_path}")
    print("[multigpu_correlation] Do NOT report a pass/fail until the real "
          "trigger condition has been read and checked against this data.")


def cmd_reproducibility(args):
    """
    C1+C2: Repeats the CEI benchmark and residency probe N times each
    (default 5) for a real spread instead of one point value.
    EVIDENCE.md already flags ~20% coefficient of variation on CEI as
    unresolved -- this produces the numbers to confirm or correct that.
    """
    from intelligence.cei_benchmark import CEIBenchmarkRunner
    from scripts.vram_residency_challenge import run_challenge

    n = args.repeats
    print(f"[reproducibility] Running CEI benchmark {n} times...")
    cei_results = []
    for i in range(n):
        r = CEIBenchmarkRunner(gpu_index=args.gpu).run(duration_s=10)
        if r:
            cei_results.append(r["cei_flops_per_joule"])
            print(f"  run {i+1}: {r['cei_flops_per_joule']:.3e} FLOPs/joule")
        else:
            print(f"  run {i+1}: FAILED (no CUDA or no power samples)")

    print(f"[reproducibility] Running residency probe {n} times...")
    residency_results = []
    for i in range(n):
        result = run_challenge(challenge_mb=512)
        if result:
            residency_results.append(result[0])
            print(f"  run {i+1}: {result[0]:.2f} ms")

    out = {
        "cei_flops_per_joule_runs": cei_results,
        "residency_latency_ms_runs": residency_results,
        "timestamp": _now_iso(),
    }
    out_path = f"b200_watchdog/reproducibility_{int(time.time())}.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    if cei_results:
        mean = sum(cei_results) / len(cei_results)
        spread = (max(cei_results) - min(cei_results)) / mean * 100
        print(f"[reproducibility] CEI spread: {spread:.1f}% of mean")
    print(f"[reproducibility] Saved: {out_path}")


def cmd_sustained_contention(args):
    """
    C3: Long-duration (default 10 min) contention test. Every prior
    contention measurement in this project was a short burst (10-60s).
    Checks whether the ~43-55% throughput loss holds steady, worsens,
    or self-corrects over a real sustained window.
    """
    import torch
    import threading

    duration_s = args.duration
    print(f"[sustained_contention] Running {duration_s}s sustained contention "
          f"test on GPU {args.gpu}...")

    collector_duration = duration_s + 30
    out_prefix = f"b200_watchdog/sustained_contention_{int(time.time())}"
    proc, log_path, jsonl_path = _launch_collector(args.gpu, collector_duration, out_prefix)
    time.sleep(10)

    stop_flag = {"stop": False}

    def competitor():
        a = torch.randn(6000, 6000, device=f"cuda:{args.gpu}")
        b = torch.randn(6000, 6000, device=f"cuda:{args.gpu}")
        while not stop_flag["stop"]:
            _ = a @ b
            torch.cuda.synchronize()

    def measured_workload():
        a = torch.randn(4096, 4096, device=f"cuda:{args.gpu}")
        b = torch.randn(4096, 4096, device=f"cuda:{args.gpu}")
        iters = 0
        start = time.time()
        checkpoints = []
        last_checkpoint = -1
        while time.time() - start < duration_s:
            _ = a @ b
            torch.cuda.synchronize()
            iters += 1
            elapsed = int(time.time() - start)
            if elapsed % 60 == 0 and elapsed != last_checkpoint:
                checkpoints.append((elapsed, iters))
                last_checkpoint = elapsed
        return iters, checkpoints

    t_comp = threading.Thread(target=competitor, daemon=True)
    t_comp.start()

    print("[sustained_contention] Running measured workload under sustained "
          "competing load, logging throughput every ~60s...")
    iters, checkpoints = measured_workload()
    stop_flag["stop"] = True

    proc.wait(timeout=collector_duration + 60)
    out = {
        "duration_s": duration_s,
        "total_iterations": iters,
        "checkpoints_elapsed_s_iters": checkpoints,
        "timestamp": _now_iso(),
    }
    out_path = f"{out_prefix}_result.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[sustained_contention] Saved: {out_path}")
    print("[sustained_contention] Compare checkpoint throughput over time -- "
          "steady = contention holds, declining = worsens, rising = self-corrects.")


def cmd_throttle_stress(args):
    """
    E2: Sustained heavy load intended to actually stress thermal/power
    limits, watching whether any of the 6 throttle_reasons flags flip
    to 'Active'. All 6 have only ever been observed reading 'Not
    Active' on an idle GPU -- a real negative control, never a real
    positive one.
    """
    import torch

    load_s = 300
    duration_s = load_s + 10
    out_prefix = f"b200_watchdog/throttle_stress_{int(time.time())}"
    proc, log_path, jsonl_path = _launch_collector(args.gpu, duration_s, out_prefix)
    time.sleep(3)

    print(f"[throttle_stress] Running {load_s}s max-heat sustained matmul...")
    a = torch.randn(12000, 12000, device=f"cuda:{args.gpu}")
    b = torch.randn(12000, 12000, device=f"cuda:{args.gpu}")
    end = time.time() + load_s
    while time.time() < end:
        _ = a @ b
        torch.cuda.synchronize()

    proc.wait(timeout=duration_s + 60)
    print(f"[throttle_stress] Done. Check the CSV's clocks_throttle_reasons.* "
          f"columns for any 'Active' value: {jsonl_path}")
    print(f"[throttle_stress] Full log: {log_path}")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("test", choices=[
        "nvlink_retest", "sequential_read", "covert_mining", "handoff",
        "multigpu_correlation", "reproducibility", "sustained_contention",
        "throttle_stress",
    ])
    parser.add_argument("--gpu", type=int, default=0)
    parser.add_argument("--repeats", type=int, default=5,
                         help="for reproducibility only")
    parser.add_argument("--duration", type=int, default=600,
                         help="seconds, for sustained_contention only")
    args = parser.parse_args()

    os.makedirs("b200_watchdog", exist_ok=True)

    dispatch = {
        "nvlink_retest": cmd_nvlink_retest,
        "sequential_read": cmd_sequential_read,
        "covert_mining": cmd_covert_mining,
        "handoff": cmd_handoff,
        "multigpu_correlation": cmd_multigpu_correlation,
        "reproducibility": cmd_reproducibility,
        "sustained_contention": cmd_sustained_contention,
        "throttle_stress": cmd_throttle_stress,
    }
    dispatch[args.test](args)


if __name__ == "__main__":
    main()
