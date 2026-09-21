"""
MoE / multi-GPU serving check, 2026-09-21. SYNTHETIC -- not hardware.

Eight H200-like GPUs holding a resident MoE model, sampled at 1 Hz, through
ONE FullDetectionPipeline (throwaway alert state + ledger per run).

At 1 Hz, token-level expert switching averages out. What survives in
nvidia-smi telemetry is (a) request-level bursts -- busy periods and idle
gaps -- and (b) per-GPU imbalance, because hot experts live on some cards.

Scenarios (same random seed, same request schedule):
  S1 steady dense     all GPUs busy, equal load, no gaps
  S2 bursty dense     request bursts + idle gaps, equal load
  S3 bursty MoE       same bursts, but load skewed across GPUs (hot/cold experts)
  S4 MoE + ghost      S3 plus a genuine ghost on GPU 7: 450 W at 0% util,
                      clocks stuck high, during a long idle gap

Checks:
  - Negative control (Watchdog README): "resident model, process alive" must
    stay silent -> no ghost alerts in S2/S3 idle gaps.
  - Positive control: the ghost on GPU 7 in S4 -- is it caught?
  - MoE-specific alerts: anything in S3 that is not in S2.
Every outcome is recorded as found. Synthetic patterns show behaviour; they
do not validate anything.
"""
import contextlib
import io
import os
import random
import sys
import tempfile
from collections import Counter
from datetime import datetime, timedelta

REPO = os.path.abspath('.')
sys.path.insert(0, REPO)

N_GPU, STEPS, SEED = 8, 400, 42
GHOST_GPU, GHOST_FROM, GHOST_TO = 7, 220, 300
FORCED_IDLE = (200, 300)                    # a long quiet spell for the ghost test
MOE_SHARE = [0.95, 0.90, 0.75, 0.60, 0.50, 0.40, 0.30, 0.25]   # hot -> cold experts
RESIDENT_MB, IDLE_W, BUSY_W_MAX = 68000, 126.0, 650.0


def schedule(seed=SEED, steps=STEPS):
    """Request-level busy/idle schedule, shared by every scenario."""
    rng = random.Random(seed)
    busy, t, state = [], 0, True
    while t < steps:
        dur = rng.randint(8, 30) if state else rng.randint(3, 20)
        busy += [state] * dur
        t += dur
        state = not state
    busy = busy[:steps]
    for i in range(*FORCED_IDLE):
        busy[i] = False
    return busy


def gpu_state(scenario, g, i, busy, rng):
    """Return (power_w, util_pct, sm_mhz) for GPU g at step i."""
    if scenario == "S1":
        u = rng.uniform(65, 75)
        return 180 + u * 6.0, u, 1980
    if scenario == "S4" and g == GHOST_GPU and GHOST_FROM <= i < GHOST_TO:
        return 450.0 + rng.uniform(-5, 5), 0.0, 1980       # genuine ghost: stuck high
    if not busy[i]:
        return IDLE_W + rng.uniform(-3, 3), 0.0, 345        # resident, idle, context alive
    share = 0.70 if scenario == "S2" else MOE_SHARE[g]
    u = max(0.0, min(100.0, share * 100 + rng.uniform(-6, 6)))
    return IDLE_W + (BUSY_W_MAX - IDLE_W) * (u / 100.0), u, 1980


def generate(scenario, seed=SEED):
    """Yield (step, gpu, P) with P the per-GPU state dict. Temperature follows
    load with thermal lag rather than jumping."""
    busy = schedule(seed)
    rng = random.Random(seed * 7 + {"S1": 1, "S2": 2, "S3": 3, "S4": 4}[scenario])
    temp = [40.0] * N_GPU
    for i in range(STEPS):
        for g in range(N_GPU):
            p, u, sm = gpu_state(scenario, g, i, busy, rng)
            target = 38 + 27 * (p - IDLE_W) / (BUSY_W_MAX - IDLE_W)
            temp[g] += (target - temp[g]) * 0.15
            yield i, g, dict(power=round(p, 1), util=round(u), umem=round(u * 0.6),
                             mem=RESIDENT_MB + rng.randint(-50, 50),
                             temp=round(temp[g], 1), sm=sm)


def value(f, g, P):
    f = f.lower()
    if f == 'index': return str(g)
    if f == 'uuid': return 'GPU-MOE-%d' % g
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
    if 'ecc' in f: return '0'
    if 'vbios' in f: return '96.00.CF.00.02'
    if 'driver' in f: return '570.124.06'
    if 'pstate' in f: return 'P0'
    if 'throttle' in f: return '0x0000000000000000'
    return '0'


def run(scenario):
    import watchdog
    from agent.telemetry import QUERY_FIELDS, parse_numeric_fields
    t0 = datetime(2026, 9, 21)
    got = []
    tmp = tempfile.mkdtemp(prefix='wd_moe_')
    os.makedirs(os.path.join(tmp, 'watchdog_data'))
    os.chdir(tmp)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            p = watchdog.FullDetectionPipeline(on_alert=lambda a: got.append(a), fleet_size=1)
            for i, g, P in generate(scenario):
                r = parse_numeric_fields({f: value(f, g, P) for f in QUERY_FIELDS})
                r['iso_timestamp'] = (t0 + timedelta(seconds=i)).isoformat()
                r['compute_apps'] = []
                p.process(r)
    finally:
        os.chdir(REPO)
    return Counter((a.get('type'), str(a.get('gpu'))) for a in got if isinstance(a, dict))


def main():
    names = {"S1": "steady dense", "S2": "bursty dense", "S3": "bursty MoE", "S4": "MoE + ghost on GPU7"}
    res = {s: run(s) for s in ("S1", "S2", "S3", "S4")}
    print("MoE / multi-GPU serving check -- SYNTHETIC, %d GPUs, %d s at 1 Hz" % (N_GPU, STEPS))
    for s in ("S1", "S2", "S3", "S4"):
        print("%s %-22s: %s" % (s, names[s], dict(res[s]) or "silent"))

    ghost = lambda c: {k: v for k, v in c.items() if "GHOST" in str(k[0])}
    print("\nCHECKS")
    neg = {**ghost(res["S2"]), **ghost(res["S3"])}
    print("  negative control -- resident model idle must stay silent (S2/S3 ghost alerts): %s -> %s"
          % (neg or "none", "PASS" if not neg else "FAIL"))
    new7 = {k: v for k, v in res["S4"].items() if k[1] == str(GHOST_GPU) and k not in res["S3"]}
    ghost7 = {k: v for k, v in new7.items() if "GHOST" in str(k[0])}
    print("  positive control -- alerts on GPU %d that appear ONLY with the ghost (S4 minus S3): %s"
          % (GHOST_GPU, new7 or "none"))
    print("    ghost-specific detection: %s" % ("CAUGHT" if ghost7 else
          "MISSED -- any ghost alert on GPU %d also fires without the ghost" % GHOST_GPU))
    energy = lambda c: sum(v for k, v in c.items() if k[0] == 'IDLE_RESIDENT_ENERGY')
    print("  reclassified to energy INFO (loaded idle, not a security alert): S2 %d, S3 %d, S4 %d"
          % (energy(res["S2"]), energy(res["S3"]), energy(res["S4"])))
    moe_only = {k: v for k, v in res["S3"].items() if k[0] not in {t for t, _ in res["S2"]}}
    print("  MoE-specific alerts (in S3, not in S2): %s" % (moe_only or "none"))
    print("\nSynthetic behaviour only. NVLink traffic is not modelled (its fields are not in"
          " QUERY_FIELDS); NVLinkContentionDetector is not exercised by this check.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
