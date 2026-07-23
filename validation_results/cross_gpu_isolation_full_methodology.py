#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog AIDR
# Project: GPU Optimizer
"""
Cross-GPU Isolation Test - Full Methodology
Writes a known pattern on GPU0 only, sustained hold and check on GPU1,
both at true 10Hz, matching the rigor of the other Full Methodology tests.
"""
import torch, subprocess, time, gc
from datetime import datetime

PATTERN = -559038737  # 0xDEADBEEF as signed int32

def s():
    r = subprocess.run(["nvidia-smi","--query-gpu=memory.used,power.draw,utilization.gpu","--format=csv,noheader,nounits"],
                        capture_output=True, text=True)
    return r.stdout.strip()

print("=== PHASE A: Writing pattern on GPU0, sustained hold ===", flush=True)
t0 = torch.full((8000, 8000), PATTERN, dtype=torch.int32, device="cuda:0")
torch.cuda.synchronize()
start = time.time()
while time.time() - start < 240:
    print("HOLD", datetime.now().isoformat(), s(), flush=True)
    time.sleep(0.1)

print("\n=== PHASE B: Releasing GPU0 memory ===", flush=True)
del t0
gc.collect()
torch.cuda.empty_cache()
time.sleep(2)

print("\n=== PHASE C: Sustained GPU1 residual check (0.1s for 240s) ===", flush=True)
t1 = torch.empty(8000, 8000, dtype=torch.int32, device="cuda:1")
torch.cuda.synchronize()
start = time.time()
while time.time() - start < 240:
    matches = (t1 == PATTERN).sum().item()
    nonzero = (t1 != 0).sum().item()
    print("CHECK", datetime.now().isoformat(), f"matches={matches} nonzero={nonzero}", s(), flush=True)
    time.sleep(0.1)

del t1
gc.collect()
torch.cuda.empty_cache()
print("\n=== DONE ===", flush=True)
