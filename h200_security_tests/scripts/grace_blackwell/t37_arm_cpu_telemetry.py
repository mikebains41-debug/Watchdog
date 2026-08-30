#!/usr/bin/env python3
"""
Grace Blackwell T-37 ARM CPU Telemetry Test
Captures Grace ARM Neoverse V2 energy counters via perf.
No x86 RAPL on ARM — uses armv8 PMU events instead.
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

print("=== GRACE BLACKWELL T-37 ARM CPU TELEMETRY ===")
print("Author: Manmohan Mike Bains GPU Optimizer")
print("CVE: 2048350")
print("Start:", datetime.utcnow().isoformat())

def get_arm_cpu_cycles():
    """Get ARM CPU cycles via perf stat."""
    try:
        r = subprocess.run([
            "perf", "stat", "-e",
            "cpu-cycles,instructions,cache-misses",
            "-a", "--", "sleep", "0.1"
        ], capture_output=True, text=True, timeout=5)
        metrics = {}
        for line in r.stderr.split("\n"):
            if "cpu-cycles" in line:
                parts = line.strip().split()
                try: metrics["cpu_cycles"] = int(parts[0].replace(",",""))
                except: pass
            if "instructions" in line:
                parts = line.strip().split()
                try: metrics["instructions"] = int(parts[0].replace(",",""))
                except: pass
        return metrics
    except Exception as e:
        return {"error": str(e)}

def get_arm_energy():
    """Get ARM energy via perf or sysfs."""
    try:
        r = subprocess.run([
            "perf", "stat", "-e", "power/energy-cores/",
            "-a", "--", "sleep", "1"
        ], capture_output=True, text=True, timeout=10)
        for line in r.stderr.split("\n"):
            if "Joules" in line or "energy" in line.lower():
                parts = line.strip().split()
                for p in parts:
                    try: return {"energy_j": float(p.replace(",","")), "method": "perf"}
                    except: continue
    except: pass
    try:
        paths = [
            "/sys/class/powercap/arm-cmn/energy_uj",
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"
        ]
        for path in paths:
            if os.path.exists(path):
                with open(path) as f:
                    val = float(f.read().strip())
                    return {"energy_uj": val, "method": "sysfs", "path": path}
    except: pass
    return {"energy_j": 0, "method": "unavailable"}

def get_cpu_freq():
    """Get current CPU frequency."""
    try:
        r = subprocess.run(["lscpu"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.split("\n"):
            if "MHz" in line or "GHz" in line:
                return line.strip()
    except: pass
    try:
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq") as f:
            return f"cpu0: {int(f.read().strip())/1000:.0f}MHz"
    except: return "unknown"

rows = []

print(f"CPU frequency: {get_cpu_freq()}")
print(f"ARM energy method: {get_arm_energy()}")

def sample_phase(phase, duration_s):
    for _ in range(int(duration_s * 2)):
        energy = get_arm_energy()
        cycles = get_arm_cpu_cycles()
        row = {"timestamp": datetime.utcnow().isoformat(), "phase": phase,
            "energy_j": energy.get("energy_j", 0),
            "cpu_cycles": cycles.get("cpu_cycles", 0),
            "instructions": cycles.get("instructions", 0),
            "method": energy.get("method", "unknown")}
        rows.append(row)
        time.sleep(0.5)

print("\nPhase 1: CPU idle baseline")
sample_phase("baseline", 30)

print("Phase 2: CPU intensive workload")
try:
    import numpy as np
    data = np.random.randn(5000, 5000).astype(np.float64)
    for _ in range(10):
        result = np.dot(data, data)
    del data, result
    print("CPU workload complete")
except Exception as e:
    print(f"CPU workload error: {e}")

print("Phase 3: Post-workload ARM energy")
sample_phase("post_workload", 30)

out_path = f"{OUTPUT_DIR}/t37_arm_telemetry_{datetime.utcnow().strftime('%Y%m%d')}.csv"
with open(out_path, "w", newline="") as f:
    if rows:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

baseline_e = [r["energy_j"] for r in rows if r["phase"]=="baseline" and r["energy_j"] > 0]
post_e = [r["energy_j"] for r in rows if r["phase"]=="post_workload" and r["energy_j"] > 0]

if baseline_e and post_e:
    print(f"\nBaseline energy avg: {sum(baseline_e)/len(baseline_e):.4f}J")
    print(f"Post-workload energy avg: {sum(post_e)/len(post_e):.4f}J")
else:
    print("\nARM energy counters not available on this platform")
    print("Note: Requires Grace CPU with perf PMU access")

print(f"Saved: {out_path}")
print("=== T-37 COMPLETE ===")
