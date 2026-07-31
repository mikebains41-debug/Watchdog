#!/usr/bin/env python3
"""Long-duration CPU stability burn-in."""
import argparse, os, time, json
from datetime import datetime

def read_ctxt():
    with open('/proc/stat') as f:
        for line in f:
            if line.startswith('ctxt '):
                return int(line.split()[1])

def read_load():
    with open('/proc/loadavg') as f:
        p = f.read().split()
    return float(p[0]), float(p[1]), float(p[2])

def read_mem():
    v = {}
    with open('/proc/meminfo') as f:
        for line in f:
            k, val = line.split(':', 1)
            v[k] = int(val.strip().split()[0])
    return v

ap = argparse.ArgumentParser()
ap.add_argument('--hours', type=float, default=24.0)
ap.add_argument('--interval', type=int, default=300)
a = ap.parse_args()

cores = len(os.sched_getaffinity(0))
os.makedirs('cpu_results', exist_ok=True)
out = f"cpu_results/burnin_{datetime.now():%Y%m%d_%H%M%S}.jsonl"
start = time.time()
end = start + a.hours * 3600
last_ctxt, last_t, n = read_ctxt(), time.time(), 0

print(f"[BURNIN] {a.hours}h, {a.interval}s interval, {cores} cores -> {out}", flush=True)

with open(out, 'a') as fh:
    while time.time() < end:
        now = time.time()
        l1, l5, l15 = read_load()
        ctxt, mem, dt = read_ctxt(), read_mem(), now - last_t
        rec = {'ts': datetime.now().isoformat(),
               'elapsed_h': round((now - start) / 3600, 3),
               'usable_cores': cores, 'load_1m': l1,
               'load_pct': round(l1 / cores * 100, 1),
               'load_5m': l5, 'load_15m': l15,
               'ctxt_per_sec': round((ctxt - last_ctxt) / dt, 1) if dt > 0 else None,
               'mem_available_gb': round(mem.get('MemAvailable', 0) / 1048576, 2)}
        fh.write(json.dumps(rec) + '\n'); fh.flush()
        n += 1
        if n % 12 == 1:
            print(f"[{rec['ts']}] load={l1:.2f} ({rec['load_pct']}%) "
                  f"ctxt/s={rec['ctxt_per_sec']} mem={rec['mem_available_gb']}GB", flush=True)
        last_ctxt, last_t = ctxt, now
        time.sleep(a.interval)

print(f"[BURNIN] done. {n} samples -> {out}", flush=True)
