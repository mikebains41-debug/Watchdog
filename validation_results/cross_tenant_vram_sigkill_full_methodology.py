#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer
"""
VRAM Residual Test - SIGKILL Full Methodology
Same rigor as the graceful-exit Full Methodology test (8000x8000,
true 10Hz sampling, sustained observation), but the writer process
is hard-killed (SIGKILL) instead of exiting normally.
"""
import torch, subprocess, time, gc, os, signal
from datetime import datetime

PATTERN = -559038737  # 0xDEADBEEF as signed int32

def s():
    r = subprocess.run(["nvidia-smi","--query-gpu=memory.used,power.draw,utilization.gpu","--format=csv,noheader,nounits"],
                        capture_output=True, text=True)
    return r.stdout.strip()

child_code = '''
import torch, time
PATTERN = -559038737
t = torch.full((8000, 8000), PATTERN, dtype=torch.int32, device="cuda:0")
torch.cuda.synchronize()
print("CHILD_READY", flush=True)
time.sleep(600)
'''
with open("/tmp/sigkill_child.py", "w") as f:
    f.write(child_code)

print("=== PHASE A: Spawning child, writing pattern, sustained hold ===", flush=True)
proc = subprocess.Popen(["python3", "/tmp/sigkill_child.py"], stdout=subprocess.PIPE, text=True)
proc.stdout.readline()  # wait for CHILD_READY
start = time.time()
while time.time() - start < 240:
    print("HOLD", datetime.now().isoformat(), s(), flush=True)
    time.sleep(0.1)

print("\n=== PHASE B: SIGKILL child ===", flush=True)
os.kill(proc.pid, signal.SIGKILL)
proc.wait()
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
