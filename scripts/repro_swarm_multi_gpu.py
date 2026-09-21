"""Swarm / full-pipeline multi-GPU check, 2026-09-21. One busy GPU, one idle GPU,
each alone vs interleaved through ONE FullDetectionPipeline (throwaway state)."""
import sys, os, io, tempfile, contextlib
from collections import Counter
from datetime import datetime, timedelta
REPO = os.path.abspath('.'); sys.path.insert(0, REPO)
from agent.telemetry import QUERY_FIELDS, parse_numeric_fields
import watchdog
BUSY = dict(power=650, util=95, umem=60, mem=60000, temp=62, sm=1980)
IDLE = dict(power=80, util=0, umem=0, mem=1, temp=35, sm=345)

def value(f, g, P):
    f = f.lower()
    if f == 'index': return str(g)
    if f == 'uuid': return 'GPU-SWARM-%d' % g
    if f == 'name': return 'NVIDIA H200'
    if 'power.draw' in f: return str(P['power'])
    if 'power.limit' in f: return '700'
    if f == 'utilization.gpu': return str(P['util'])
    if f == 'utilization.memory': return str(P['umem'])
    if f == 'memory.used': return str(P['mem'])
    if f == 'memory.total': return '143771'
    if 'temperature' in f: return str(P['temp'])
    if 'clocks.mem' in f: return '3201'
    if f.startswith('clocks.') and 'throttle' not in f: return str(P['sm'])
    if 'pcie.link.gen' in f: return '5'
    if 'pcie.link.width' in f: return '16'
    if 'vbios' in f: return '96.00.CF.00.02'
    if 'driver' in f: return '570.124.06'
    if 'pstate' in f: return 'P0'
    if 'throttle' in f: return '0x0000000000000000'
    return '0'

T0 = datetime(2026, 9, 21)
def row(g, P, i):
    r = parse_numeric_fields({f: value(f, g, P) for f in QUERY_FIELDS})
    r['iso_timestamp'] = (T0 + timedelta(seconds=i)).isoformat()
    r['compute_apps'] = []
    return r

def run(feed, cycles=40):
    got = []
    tmp = tempfile.mkdtemp(prefix='wd_swarm_')
    os.makedirs(os.path.join(tmp, 'watchdog_data')); os.chdir(tmp)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            p = watchdog.FullDetectionPipeline(on_alert=lambda a: got.append(a), fleet_size=1)
            for i in range(cycles):
                for g, P in feed:
                    p.process(row(g, P, i))
    finally:
        os.chdir(REPO)
    return Counter((a.get('type'), str(a.get('gpu'))) for a in got if isinstance(a, dict))

busy, idle, mixed = run([(0, BUSY)]), run([(1, IDLE)]), run([(0, BUSY), (1, IDLE)])
alone = busy + idle
print("GPU0 busy alone :", dict(busy) or "silent")
print("GPU1 idle alone :", dict(idle) or "silent")
print("mixed           :", dict(mixed) or "silent")
print("FALSE WHEN MIXED (fires only mixed)   :", sorted(k for k in mixed if k[0] not in {t for t, _ in alone}) or "none")
print("MISSED WHEN MIXED (fires alone only)  :", sorted(k for k in alone if k not in mixed) or "none")


# --- Positive control: a REAL precursor on GPU1 must still be predicted, on GPU1 ---
def run_seq(cycles, gen):
    got = []
    tmp = tempfile.mkdtemp(prefix='wd_swarm_')
    os.makedirs(os.path.join(tmp, 'watchdog_data')); os.chdir(tmp)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            p = watchdog.FullDetectionPipeline(on_alert=lambda a: got.append(a), fleet_size=1)
            for i in range(cycles):
                for g, P in gen(i):
                    p.process(row(g, P, i))
    finally:
        os.chdir(REPO)
    return Counter((a.get('type'), str(a.get('gpu'))) for a in got if isinstance(a, dict))

def winding_down(i):
    f = 0.0 if i < 20 else min(1.0, (i - 19) / 10.0)
    p1 = dict(power=650 + (130 - 650) * f, util=95 * (1 - f), umem=60 * (1 - f),
              mem=60000, temp=62 - 20 * f, sm=1980 + (345 - 1980) * f)
    return [(0, BUSY), (1, p1)]

res = run_seq(45, winding_down)
hit = {g for (t, g) in res if t == 'GHOST_POWER_PREDICTED'}
print("POSITIVE CONTROL real precursor on GPU1, GPU0 busy :",
      "PASS" if hit == {'1'} else "FAIL", "(predicted on gpu %s)" % (sorted(hit) or "none"))
