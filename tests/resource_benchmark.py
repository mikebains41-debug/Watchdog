#!/usr/bin/env python3
# Watchdog AIDR - Resource Overhead Benchmark
# Measures Watchdog's own CPU/memory overhead processing synthetic
# telemetry through the real DetectionPipeline. No GPU/nvidia-smi
# needed -- fully runnable on this device.

import sys
import os
import time
import json
import psutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
from engines import DetectionPipeline


def make_synthetic_row(i):
    return {
        "power.draw": 200 + (i % 50),
        "utilization.gpu": 40 + (i % 30),
        "memory.used": 8000 + (i % 500),
        "temperature.gpu": 60 + (i % 10),
        "index": 0,
        "iso_timestamp": "2026-01-01T00:00:00Z",
    }


def run_benchmark(iterations=10000):
    print("=== Watchdog Resource Overhead Benchmark ===")
    print(f"Processing {iterations} synthetic telemetry rows through DetectionPipeline\n")

    pipeline = DetectionPipeline()
    process = psutil.Process()

    cpu_samples = []
    mem_samples = []

    start_time = time.time()
    for i in range(iterations):
        row = make_synthetic_row(i)
        pipeline.process(row)

        if i % 1000 == 0:
            mem_mb = process.memory_info().rss / 1024 / 1024
            cpu_pct = process.cpu_percent(interval=None)
            mem_samples.append(mem_mb)
            cpu_samples.append(cpu_pct)
            print(f"[{i}/{iterations}] Memory: {mem_mb:.1f}MB, CPU: {cpu_pct:.1f}%")

    elapsed = time.time() - start_time
    rows_per_sec = iterations / elapsed if elapsed > 0 else 0

    print("\n=== SUMMARY ===")
    print(f"Total time: {elapsed:.2f}s for {iterations} rows ({rows_per_sec:.0f} rows/sec)")

    if mem_samples:
        mem_variance = max(mem_samples) - min(mem_samples)
        print(f"Memory: min={min(mem_samples):.1f}MB, max={max(mem_samples):.1f}MB, variance={mem_variance:.1f}MB")

    results = {
        "iterations": iterations, "elapsed_s": elapsed, "rows_per_sec": rows_per_sec,
        "memory_samples_mb": mem_samples, "cpu_samples_pct": cpu_samples,
    }
    with open("resource_benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nResults saved: resource_benchmark_results.json")

    return mem_samples and (max(mem_samples) - min(mem_samples)) < 5


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=10000)
    args = parser.parse_args()
    success = run_benchmark(iterations=args.iterations)
    sys.exit(0 if success else 1)
