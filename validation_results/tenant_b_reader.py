#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
# Project: GPU Optimizer
"""
Cross-Tenant PoC - Tenant B (Reader)
Genuinely separate process from Tenant A. Allocates VRAM and reads
raw content BEFORE writing anything, scanning for Tenant A's marker.
Repeats multiple times since the allocator may not return the same
physical pages immediately.
"""
import torch, time

MARKER = "NELSON_VICENTE_CROSS_TENANT_MARKER_7F3A9C2E8B1D"
marker_bytes = MARKER.encode("utf-8")

print("=== TENANT B: Scanning fresh VRAM allocations for Tenant A's marker ===", flush=True)
hits_total = 0
for attempt in range(20):
    t = torch.empty(200_000_000, dtype=torch.uint8, device="cuda:0")
    torch.cuda.synchronize()
    raw = bytes(t.cpu().numpy().tobytes())
    found = raw.count(marker_bytes)
    hits_total += found
    print(f"Attempt {attempt+1}: marker occurrences found = {found}", flush=True)
    del t
    torch.cuda.empty_cache()
    time.sleep(1)

print(f"\n=== RESULT: total marker occurrences across 20 attempts = {hits_total} ===", flush=True)
if hits_total > 0:
    print("RECOVERY CONFIRMED - Tenant A's marker was recovered by Tenant B", flush=True)
else:
    print("CLEAN - no marker recovered, isolation holds for this test", flush=True)
