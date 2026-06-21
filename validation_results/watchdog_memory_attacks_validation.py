#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer
"""
Watchdog Memory Attacks Validation - Full Rigor
Feeds live nvidia-smi data into CacheSideChannelDetector,
MIGPartitionDesyncDetector, and SequentialVRAMReadDetector.
Phase A: baseline (idle), 240s. Phase B: bulk memory-bandwidth
workload (separate subprocess, high mem util, low compute util)
running simultaneously, 240s.
"""
import sys, subprocess, time
from datetime import datetime
sys.path.insert(0, "/workspace/Watchdog")
from detection.memory_attacks import CacheSideChannelDetector, MIGPartitionDesyncDetector, SequentialVRAMReadDetector

d1 = CacheSideChannelDetector()
d2 = MIGPartitionDesyncDetector()
d3 = SequentialVRAMReadDetector()

def get_row():
    r = subprocess.run(["nvidia-smi","--query-gpu=index,utilization.gpu,utilization.memory,memory.used,memory.total",
                         "--format=csv,noheader,nounits"], capture_output=True, text=True)
    line = r.stdout.strip().split("\n")[0]
    parts = [p.strip() for p in line.split(",")]
    return {"index": parts[0], "utilization.gpu": parts[1], "utilization.memory": parts[2],
            "memory.used": parts[3], "memory.total": parts[4], "iso_timestamp": datetime.now().isoformat()}

def run_phase(label, duration):
    a1 = a2 = a3 = 0
    start = time.time()
    count = 0
    while time.time() - start < duration:
        row = get_row()
        count += 1
        r1 = d1.update(row); r2 = d2.update(row); r3 = d3.update(row)
        if r1: a1 += 1
        if r2: a2 += 1
        if r3: a3 += 1
        print(label, count, row, "CACHE:", r1, "MIG:", r2, "SEQ:", r3, flush=True)
    return count, a1, a2, a3

print("=== PHASE A: Baseline, 240s ===", flush=True)
bc, ba1, ba2, ba3 = run_phase("BASELINE", 240)

print("\n=== PHASE B: Starting bulk memory-bandwidth workload subprocess (240s) ===", flush=True)
proc = subprocess.Popen(["python3", "-c",
    "import torch,time\n"
    "big = torch.empty(200_000_000, dtype=torch.float32, device='cuda:0')\n"
    "start=time.time()\n"
    "while time.time()-start < 240:\n"
    "    _ = big.sum().item()\n"])
time.sleep(3)

cc, ca1, ca2, ca3 = run_phase("CONTENTION", 240)
proc.wait()

print(f"\n=== SUMMARY ===", flush=True)
print(f"BASELINE ({bc} samples): cache={ba1} mig={ba2} seq={ba3}", flush=True)
print(f"CONTENTION ({cc} samples): cache={ca1} mig={ca2} seq={ca3}", flush=True)
print("=== DONE ===", flush=True)
