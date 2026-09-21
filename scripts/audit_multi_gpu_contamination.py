"""Audit every engine in FullDetectionPipeline for cross-GPU contamination.
Two GPUs, each steady and clean on its own but different from each other
(as on a mixed node). Alerts that appear ONLY when their rows are interleaved
through one pipeline are false alarms caused by mixing, not by either GPU."""
import sys, io, contextlib
from collections import Counter
from datetime import datetime, timedelta
import os, tempfile
REPO = os.path.abspath('.')
sys.path.insert(0, REPO)
from agent.telemetry import QUERY_FIELDS, parse_numeric_fields
import watchdog

PROFILES = [
    dict(name='NVIDIA H200', power=300.0, limit=700.0, umem=20, mem=20000, total=143771,
         temp=45, sm=1980, memclk=3201, gen=5, width=16, ecc=0, vbios='96.00.CF.00.02', fan=30),
    dict(name='NVIDIA H100 80GB HBM3', power=350.0, limit=600.0, umem=25, mem=30000, total=81559,
         temp=55, sm=1755, memclk=2619, gen=4, width=16, ecc=12, vbios='96.00.A1.00.01', fan=40),
]

def value(field, g, P):
    f = field.lower()
    if f == 'index': return str(g)
    if f == 'uuid': return 'GPU-AUDIT-%d' % g
    if f == 'name': return P['name']
    if 'power.draw' in f: return str(P['power'])
    if 'power.limit' in f: return str(P['limit'])
    if f == 'utilization.gpu': return '50'
    if f == 'utilization.memory': return str(P['umem'])
    if f == 'memory.used': return str(P['mem'])
    if f == 'memory.total': return str(P['total'])
    if 'temperature' in f: return str(P['temp'])
    if 'clocks.mem' in f: return str(P['memclk'])
    if f.startswith('clocks.') and 'throttle' not in f: return str(P['sm'])
    if 'pcie.link.gen' in f: return str(P['gen'])
    if 'pcie.link.width' in f: return str(P['width'])
    if 'ecc' in f and 'uncorr' in f: return '0'
    if 'ecc' in f: return str(P['ecc'])
    if 'vbios' in f: return P['vbios']
    if 'driver' in f: return '570.124.06'
    if 'pstate' in f: return 'P0'
    if 'fan' in f: return str(P['fan'])
    if 'throttle' in f: return '0x0000000000000000'
    return '0'

T0 = datetime(2026, 9, 21)
def make_row(g, i):
    r = {f: value(f, g, PROFILES[g]) for f in QUERY_FIELDS}
    r = parse_numeric_fields(r)
    r['iso_timestamp'] = (T0 + timedelta(seconds=i)).isoformat()
    r['compute_apps'] = []
    return r

def run(order, cycles=150):
    got = []
    _tmp = tempfile.mkdtemp(prefix='wd_audit_')
    os.makedirs(os.path.join(_tmp, 'watchdog_data'))
    os.chdir(_tmp)  # fresh alert state + ledger per run; never the real ones
    p = watchdog.FullDetectionPipeline(on_alert=lambda a: got.append(a), fleet_size=1)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        for i in range(cycles):
            for g in order:
                out = p.process(make_row(g, i)) or []
                got.extend(a for a in out if isinstance(a, dict) and a not in got)
    os.chdir(REPO)
    errs = sorted({l.strip() for l in buf.getvalue().splitlines() if 'rror' in l or 'xception' in l})
    for e in errs[:3]:
        print('    [hidden] ' + e[:140])
    return Counter((a.get('type'), str(a.get('gpu'))) for a in got if isinstance(a, dict))

alone0, alone1, mixed = run([0]), run([1]), run([0, 1])
print("GPU0 alone :", dict(alone0) or "silent")
print("GPU1 alone :", dict(alone1) or "silent")
print("mixed      :", dict(mixed) or "silent")
alone_types = {t for t, _ in alone0} | {t for t, _ in alone1}
bad = {k: v for k, v in mixed.items() if k[0] not in alone_types}
print("\nCROSS-GPU CONTAMINATION (fires only when GPUs are mixed):")
for (t, g), n in sorted(bad.items()):
    print("  %-40s gpu=%s  x%d" % (t, g, n))
if not bad:
    print("  none")


# --- Positive controls: the wrapped engines must still catch REAL events ---
def run_with(order, cycles, mutate):
    got = []
    _tmp = tempfile.mkdtemp(prefix='wd_audit_')
    os.makedirs(os.path.join(_tmp, 'watchdog_data'))
    os.chdir(_tmp)  # fresh alert state + ledger per run; never the real ones
    p = watchdog.FullDetectionPipeline(on_alert=lambda a: got.append(a), fleet_size=1)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        for i in range(cycles):
            for g in order:
                r = make_row(g, i)
                mutate(r, g, i)
                out = p.process(r) or []
                got.extend(a for a in out if isinstance(a, dict) and a not in got)
    os.chdir(REPO)
    errs = sorted({l.strip() for l in buf.getvalue().splitlines() if 'rror' in l or 'xception' in l})
    for e in errs[:3]:
        print('    [hidden] ' + e[:140])
    return Counter((a.get('type'), str(a.get('gpu'))) for a in got if isinstance(a, dict))

def ecc_rise(r, g, i):
    if g == 1 and i >= 100:
        for k in list(r):
            if 'ecc' in k.lower() and 'uncorr' not in k.lower():
                r[k] = 12 + (i - 99) * 2

def temp_jump(r, g, i):
    if g == 1 and i >= 120:
        for k in list(r):
            if 'temperature' in k.lower():
                r[k] = 75

print("\nPOSITIVE CONTROLS (mixed GPUs, real event on GPU1 only):")
for label, fn, want in (("ECC errors rising on GPU1", ecc_rise, "ECC_CORRECTABLE_TREND"),
                        ("temperature jump on GPU1", temp_jump, "LASER_INJECTION")):
    for order, tag in (([1], "GPU1 alone"), ([0, 1], "mixed")):
        res = run_with(order, 180, fn)
        hit = {g for (t, g) in res if t == want}
        verdict = "PASS" if hit == {"1"} else "FAIL"
        print("  %-28s %-10s %s  (%s on gpu %s)" % (label, tag, verdict, want, sorted(hit) or "none"))
