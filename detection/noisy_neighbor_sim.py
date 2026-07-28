#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
Noisy-neighbor simulator - creates generic, irregular GPU memory access
contention to test whether CacheTimingProbeDetector responds differently
under contention vs. an idle baseline. NOT an attack - doesn't extract or
infer any data, just creates realistic background load patterns to test
detector responsiveness.
"""
import torch
import time
import random

def run_noisy_neighbor(gpu_index=0, duration_s=60):
    print(f"Starting noisy-neighbor simulation on cuda:{gpu_index} for {duration_s}s", flush=True)
    buf = torch.empty(1024 * 1024, dtype=torch.float32, device=f'cuda:{gpu_index}')
    start = time.time()
    while time.time() - start < duration_s:
        offset = random.randint(0, 1024 * 1024 - 1000)
        size = random.randint(100, 1000)
        _ = buf[offset:offset + size].sum().item()
        time.sleep(random.uniform(0.0001, 0.005))
    print("Noisy-neighbor simulation complete", flush=True)

if __name__ == "__main__":
    run_noisy_neighbor()
