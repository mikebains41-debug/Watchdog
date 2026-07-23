#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
# Project: GPU Optimizer
"""
Quantified Contention Impact Benchmark
Measures real matmul throughput (iterations/sec) under two conditions:
baseline (no contention) and during noisy-neighbor contention.
Different from the Watchdog detector validation - this measures actual
performance impact, not whether a detector alerts.
"""
import torch, time, subprocess

def run_benchmark(duration_s, label):
    size = 4096
    a = torch.randn(size, size, device="cuda:0")
    b = torch.randn(size, size, device="cuda:0")
    torch.cuda.synchronize()
    count = 0
    start = time.time()
    while time.time() - start < duration_s:
        c = torch.matmul(a, b)
        torch.cuda.synchronize()
        count += 1
    elapsed = time.time() - start
    throughput = count / elapsed
    print(f"{label}: {count} matmuls in {elapsed:.2f}s = {throughput:.2f} iter/sec", flush=True)
    return throughput

print("=== PHASE A: Baseline benchmark (60s, no contention) ===", flush=True)
baseline_throughput = run_benchmark(60, "BASELINE")

print("\n=== PHASE B: Starting noisy-neighbor contention, then benchmarking (60s) ===", flush=True)
proc = subprocess.Popen(["python3", "/workspace/Watchdog/detection/noisy_neighbor_sim.py"])
time.sleep(3)
contention_throughput = run_benchmark(60, "CONTENTION")
proc.wait()

pct_change = ((contention_throughput - baseline_throughput) / baseline_throughput) * 100
print(f"\n=== RESULT: baseline={baseline_throughput:.2f} iter/sec, contention={contention_throughput:.2f} iter/sec, change={pct_change:+.1f}% ===", flush=True)
print("=== DONE ===", flush=True)
