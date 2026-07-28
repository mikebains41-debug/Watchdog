#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
# Project: GPU Optimizer
"""
VRAM Residual Test - Full Methodology (corrected)
Matches test 4's exact sampling rate (0.1s / 10Hz) throughout, while
adding real byte-level pattern verification, which test 4 never did.
"""
import torch, subprocess, time, gc
from datetime import datetime

PATTERN = -559038737  # -559038737 as signed int32

def s():
    r = subprocess.run(["nvidia-smi","--query-gpu=memory.used,power.draw,utilization.gpu","--format=csv,noheader,nounits"],
                        capture_output=True, text=True)
    return r.stdout.strip()

print("=== PHASE A: Writing known pattern, sustained hold ===", flush=True)
t = torch.full((8000, 8000), PATTERN, dtype=torch.int32, device="cuda:0")
torch.cuda.synchronize()
start = time.time()
while time.time() - start < 240:
    print("HOLD", datetime.now().isoformat(), s(), flush=True)
    time.sleep(0.1)

print("\n=== PHASE B: Releasing memory ===", flush=True)
del t
gc.collect()
torch.cuda.empty_cache()
time.sleep(2)

print("\n=== PHASE C: Sustained byte-level residual monitoring (0.1s for 240s) ===", flush=True)
t2 = torch.empty(8000, 8000, dtype=torch.int32, device="cuda:0")
torch.cuda.synchronize()
start = time.time()
while time.time() - start < 240:
    matches = (t2 == PATTERN).sum().item()
    nonzero = (t2 != 0).sum().item()
    print("CHECK", datetime.now().isoformat(), f"matches={matches} nonzero={nonzero}", s(), flush=True)
    time.sleep(0.1)

del t2
gc.collect()
torch.cuda.empty_cache()
print("\n=== DONE ===", flush=True)
