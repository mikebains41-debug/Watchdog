#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
# Project: GPU Optimizer
"""
Watchdog Validation Test - Full Rigor
Same 240s/240s sustained structure as the VRAM Full Methodology tests.
Runs CacheTimingProbeDetector continuously for 4 minutes baseline (idle),
then continuously for 4 minutes during noisy-neighbor contention.
First real hardware run for this detector - validating basic function,
not proving attack detection.
"""
import sys, subprocess, time
sys.path.insert(0, "/workspace/Watchdog")
from detection.cache_timing_probe import CacheTimingProbeDetector

detector = CacheTimingProbeDetector()

print("=== PHASE A: Baseline probing, sustained 240s, no contention ===", flush=True)
baseline_alerts = 0
baseline_count = 0
start = time.time()
while time.time() - start < 240:
    result = detector.probe(gpu_index=0)
    baseline_count += 1
    print(f"BASELINE probe {baseline_count}", result, flush=True)
    if result:
        baseline_alerts += 1

print("\n=== PHASE B: Starting sustained noisy-neighbor contention (240s) ===", flush=True)
proc = subprocess.Popen(["python3", "-c",
    "import sys; sys.path.insert(0,'/workspace/Watchdog'); "
    "from detection.noisy_neighbor_sim import run_noisy_neighbor; "
    "run_noisy_neighbor(gpu_index=0, duration_s=240)"])
time.sleep(3)

print("\n=== PHASE C: Probing DURING contention, sustained 240s ===", flush=True)
contention_alerts = 0
contention_count = 0
start = time.time()
while time.time() - start < 240:
    result = detector.probe(gpu_index=0)
    contention_count += 1
    print(f"CONTENTION probe {contention_count}", result, flush=True)
    if result:
        contention_alerts += 1

proc.wait()
print(f"\n=== SUMMARY: baseline_alerts={baseline_alerts}/{baseline_count}  contention_alerts={contention_alerts}/{contention_count} ===", flush=True)
print("=== DONE ===", flush=True)
