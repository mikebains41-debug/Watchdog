#!/usr/bin/env python3
"""
Grace Blackwell T-36 Rack-Scale Ghost Power Test
Tests cumulative ghost power across multiple GPUs in NVL72 rack.
Author: Manmohan Mike Bains GPU Optimizer
CVE: 2048350
"""
import time
import json
import csv
import os
import subprocess
from datetime import datetime

OUTPUT_DIR = "./results/grace_blackwell"
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=== GRACE BLACKWELL T-36 RACK-SCALE GHOST POWER ===")
print("Author: Manmohan Mike Bains GPU Optimizer")
print("CVE: 2048350")
print("Start:", datetime.utcnow().isoformat())

def get_all_gpu_power():
    try:
        r = subprocess.run(["nvidia-smi","--query-gpu=index,power.draw,utilization.gpu,memory.used",
            "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5)
        gpus = []
        for line in r.stdout.strip().split("\n"):
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 4:
                gpus.append({"gpu_id": int(parts[0]), "power_w": float(parts[1]),
                    "util_pct": float(parts[2]), "vram_mb": float(parts[3])})
        return gpus
    except: return []

rows = []
HZ = 5

def sample_phase(phase, duration_s):
    for _ in range(int(duration_s * HZ)):
        gpus = get_all_gpu_power()
        total_power = sum(g["power_w"] for g in gpus)
        row = {"timestamp": datetime.utcnow().isoformat(), "phase": phase,
            "total_rack_power_w": total_power, "gpu_count": len(gpus),
            "gpu_details": json.dumps(gpus)}
        rows.append(row)
        time.sleep(1/HZ)

print("Phase 1: Baseline all GPUs idle")
sample_phase("baseline", 30)

gpus = get_all_gpu_power()
gpu_count = len(gpus)
print(f"Detected {gpu_count} GPUs in system")

print("Phase 2: Loading subset of GPUs...")
try:
    import torch
    workload_gpus = min(gpu_count, 4)
    tensors = []
    for i in range(workload_gpus):
        if torch.cuda.device_count() > i:
            with torch.cuda.device(i):
                t = torch.randn(8192, 8192, device=f"cuda:{i}")
                tensors.append(t)
    print(f"Loaded {workload_gpus} GPUs")
    sample_phase("subset_loaded", 30)
    for t in tensors:
        del t
    tensors = []
    import gc
    gc.collect()
    torch.cuda.empty_cache()
    print("Subset workload deleted")
except Exception as e:
    print(f"Workload error: {e}")

print("Phase 3: Post-workload — measuring rack-scale ghost power")
sample_phase("post_workload", 60)

out_path = f"{OUTPUT_DIR}/t36_rack_scale_{datetime.utcnow().strftime('%Y%m%d')}.csv"
with open(out_path, "w", newline="") as f:
    if rows:
        writer = csv.DictWriter(f, fieldnames=["timestamp","phase","total_rack_power_w","gpu_count","gpu_details"])
        writer.writeheader()
        writer.writerows(rows)

baseline_p = [r["total_rack_power_w"] for r in rows if r["phase"]=="baseline"]
post_p = [r["total_rack_power_w"] for r in rows if r["phase"]=="post_workload"]

if baseline_p and post_p:
    b_avg = sum(baseline_p)/len(baseline_p)
    p_avg = sum(post_p)/len(post_p)
    delta = p_avg - b_avg
    print(f"\nBaseline rack power: {b_avg:.1f}W")
    print(f"Post-workload rack power: {p_avg:.1f}W")
    print(f"Rack-scale ghost power delta: {delta:.1f}W")
    print(f"Ghost power per GPU: {delta/max(gpu_count,1):.1f}W")
    print(f"Rack-scale ghost detected: {'YES CVE-2048350' if delta > 50 else 'NO'}")

print(f"Saved: {out_path}")
print("=== T-36 COMPLETE ===")
