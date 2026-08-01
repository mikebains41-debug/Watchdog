#!/usr/bin/env python3
"""Test: CPU Burn-in Stability"""
import os, time, json
from datetime import datetime

cores = len(os.sched_getaffinity(0))
out = f"cpu_new_tests/burnin_{datetime.now():%Y%m%d_%H%M%S}.jsonl"
print(f"[BURNIN] {cores} cores -> {out}")
for i in range(10):
    with open("/proc/loadavg", "r") as f:
        load = f.read().split()
    rec = {"ts": datetime.now().isoformat(), "load": float(load[0]), "cores": cores}
    with open(out, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"{rec['ts']} load={rec['load']:.2f}")
    time.sleep(5)
print("DONE")
