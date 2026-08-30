#!/usr/bin/env python3
"""
Grace Blackwell T-35 NVLink-C2C Ghost Power Test
Measures CPU/GPU power propagation through coherent interconnect.
Author: Manmohan Mike Bains GPU Optimizer
CVE: 2048350
"""
import time
import json
import csv
import os
import subprocess
from datetime import datetime
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

OUTPUT_DIR = "./results/grace_blackwell"
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=== GRACE BLACKWELL T-35 NVLINK-C2C GHOST POWER ===")
print("Author: Manmohan Mike Bains GPU Optimizer")
print("CVE: 2048350")
print("Start:", datetime.utcnow().isoformat())

def get_gpu_power(gpu_id=0):
    try:
        r = subprocess.run(["nvidia-smi","--query-gpu=power.draw",
            "--format=csv,noheader,nounits",f"--id={gpu_id}"],
            capture_output=True, text=True, timeout=5)
        return float(r.stdout.strip())
    except: return 0.0

def get_nvlink_traffic(gpu_id=0):
    try:
        r = subprocess.run(["nvidia-smi","nvlink","--status","-i",str(gpu_id)],
            capture_output=True, text=True, timeout=5)
        tx, rx = 0, 0
        for line in r.stdout.split("\n"):
            if "Tx" in line:
                for p in line.split():
                    try: tx += float(p); break
                    except: continue
            if "Rx" in line:
                for p in line.split():
                    try: rx += float(p); break
                    except: continue
        return tx + rx
    except: return 0.0

rows = []
HZ = 10

def sample_phase(phase, duration_s):
    for _ in range(int(duration_s * HZ)):
        gpu_p = get_gpu_power(0)
        nvlink = get_nvlink_traffic(0)
        row = {"timestamp": datetime.utcnow().isoformat(), "phase": phase,
            "gpu_power_w": gpu_p, "nvlink_total_kib_s": nvlink}
        rows.append(row)
        time.sleep(1/HZ)

print("Phase 1: Baseline — all idle")
sample_phase("baseline", 30)

print("Phase 2: CPU-heavy workload via memory copies...")
try:
    import numpy as np
    data = np.random.randn(10000, 10000).astype(np.float32)
    for _ in range(5):
        copy = data.copy()
    del data, copy
    print("CPU workload complete")
except Exception as e:
    print(f"CPU workload error: {e}")

print("Phase 3: Post-CPU-workload — watching for GPU ghost power via NVLink")
sample_phase("post_cpu_workload", 60)

print("Phase 4: GPU workload...")
try:
    import torch
    x = torch.randn(8192, 8192)
    for _ in range(3):
        x = torch.matmul(x, x)
    del x
    print("GPU workload complete")
except Exception as e:
    print(f"GPU workload error: {e}")

print("Phase 5: Post-GPU-workload — watching NVLink residual activity")
sample_phase("post_gpu_workload", 60)

out_path = f"{OUTPUT_DIR}/t35_nvlink_ghost_{datetime.utcnow().strftime('%Y%m%d')}.csv"
with open(out_path, "w", newline="") as f:
    if rows:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

baseline_p = [r["gpu_power_w"] for r in rows if r["phase"]=="baseline"]
post_cpu_p = [r["gpu_power_w"] for r in rows if r["phase"]=="post_cpu_workload"]
post_gpu_p = [r["gpu_power_w"] for r in rows if r["phase"]=="post_gpu_workload"]
baseline_nl = [r["nvlink_total_kib_s"] for r in rows if r["phase"]=="baseline"]
post_gpu_nl = [r["nvlink_total_kib_s"] for r in rows if r["phase"]=="post_gpu_workload"]

if baseline_p and post_cpu_p:
    cpu_induced_gpu_delta = sum(post_cpu_p)/len(post_cpu_p) - sum(baseline_p)/len(baseline_p)
    print(f"\nCPU-induced GPU power delta: {cpu_induced_gpu_delta:.2f}W")
    print(f"NVLink-C2C coupling detected: {'YES' if cpu_induced_gpu_delta > 5 else 'NO'}")

if baseline_nl and post_gpu_nl:
    nvlink_residual = sum(post_gpu_nl)/len(post_gpu_nl) - sum(baseline_nl)/len(baseline_nl)
    print(f"NVLink residual traffic post-GPU: {nvlink_residual:.0f} KiB/s")
    print(f"Interconnect ghost activity: {'YES' if nvlink_residual > 1000 else 'NO'}")

print(f"Saved: {out_path}")
print("=== T-35 COMPLETE ===")
