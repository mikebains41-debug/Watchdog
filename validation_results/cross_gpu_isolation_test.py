#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
# Project: GPU Optimizer
"""
Cross-GPU VRAM Isolation Test
Measures GPU1's reported memory usage before and after a large workload
runs ONLY on GPU0. If GPU1's memory.used rises despite zero active
workload, that's the cross-GPU isolation/reporting bleed finding
(matches the documented H200 result: GPU1 picked up residual VRAM
accounting from GPU0 with no GPU1 workload).

This tests memory ACCOUNTING bleed across the GPU boundary via NVML
reporting - it does not attempt to read GPU0's actual tensor data from
GPU1, which is a separate, more severe claim not yet established.

Repository: https://github.com/mikebains41-debug/ai-gpu-energy-optimizer-
"""
import torch
import subprocess
import time
import gc

PATTERN_SIZE = 8192

def get_memory_used(gpu_id):
    r = subprocess.run(
        ["nvidia-smi", f"--id={gpu_id}", "--query-gpu=memory.used,utilization.gpu",
         "--format=csv,noheader,nounits"],
        capture_output=True, text=True
    )
    parts = r.stdout.strip().split(", ")
    return {"mem_used_mb": float(parts[0]), "util_pct": float(parts[1])}

def main():
    print("=== Cross-GPU Isolation Test ===", flush=True)

    print("Measuring GPU1 baseline (before any GPU0 workload)...", flush=True)
    baseline = get_memory_used(1)
    print(f"GPU1 baseline: {baseline['mem_used_mb']}MB used, {baseline['util_pct']}% util", flush=True)

    print(f"Allocating a known pattern on GPU0 only ({PATTERN_SIZE}x{PATTERN_SIZE})...", flush=True)
    t = torch.full((PATTERN_SIZE, PATTERN_SIZE), -559038737, dtype=torch.int32, device="cuda:0")
    torch.cuda.synchronize()
    time.sleep(2)

    gpu0_after = get_memory_used(0)
    print(f"GPU0 after allocation: {gpu0_after['mem_used_mb']}MB used, {gpu0_after['util_pct']}% util", flush=True)

    print("Re-checking GPU1 while GPU0 holds the allocation (GPU1 untouched)...", flush=True)
    during = get_memory_used(1)
    print(f"GPU1 during: {during['mem_used_mb']}MB used, {during['util_pct']}% util", flush=True)

    leaked_mb = during["mem_used_mb"] - baseline["mem_used_mb"]
    print(f"\nGPU1 memory.used delta while only GPU0 was active: {leaked_mb:.1f}MB", flush=True)
    if leaked_mb > 10:
        print(f"CROSS_GPU_ISOLATION_FAILURE: GPU1 reported {leaked_mb:.1f}MB usage with zero active GPU1 workload", flush=True)
    else:
        print("No meaningful GPU1 memory bleed detected on this run", flush=True)

    print("\nCleaning up GPU0 allocation...", flush=True)
    del t
    gc.collect()
    torch.cuda.empty_cache()

    print("Re-checking GPU1 after GPU0 cleanup...", flush=True)
    after = get_memory_used(1)
    print(f"GPU1 after GPU0 cleanup: {after['mem_used_mb']}MB used, {after['util_pct']}% util", flush=True)

if __name__ == "__main__":
    main()
