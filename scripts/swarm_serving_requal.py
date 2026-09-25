"""
Swarm requalification against NORMAL SERVING -- 2026-09-21. SYNTHETIC.

The swarm qualification (2026-09-20, scripts/swarm_qualification.py) measured
0% false positives -- on a clean corpus that never included ordinary inference
serving, where a batch ends, power drops, utilisation hits 0 and the model
stays loaded. scripts/repro_moe_multi_gpu.py then showed GhostPowerPredictor
firing on every GPU in exactly that state.

This drives the REAL swarm agents (the live pipeline's _PerGPUSwarm, one swarm
per GPU) over the same normal-serving scenarios, and counts every raw alert
BEFORE dedup, per agent, per GPU:

  S1 steady dense  -- always busy, equal load
  S2 bursty dense  -- request bursts and idle gaps, model resident
  S3 bursty MoE    -- same bursts, uneven load across GPUs

All three are negative controls: nothing wrong is happening. Any alert is a
false positive for the agent that raised it.

LIMITS: synthetic telemetry (H200-like numbers). Several agents use wall-clock
cooldowns, so a run processed faster than real time can under-count repeats --
which is why the main measure is how many GPUs an agent fired on at all.
Agents needing fields nothing collects (CEI for agent2/agent5) cannot fire
here and are reported as untested, not as passing.
"""
import contextlib
import io
import os
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta

REPO = os.path.abspath('.')
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, 'scripts'))

SCENARIOS = (("S1", "steady dense"), ("S2", "bursty dense"), ("S3", "bursty MoE"))


def run(sc, moe, swarm_cls, adapt, QUERY_FIELDS, parse_numeric_fields):
    with contextlib.redirect_stdout(io.StringIO()):
        sw = swarm_cls(gpu_arch='H200')
    gpus = defaultdict(set)
    raw = defaultdict(int)
    t0 = datetime(2026, 9, 21)
    for i, g, P in moe.generate(sc):
        r = parse_numeric_fields({f: moe.value(f, g, P) for f in QUERY_FIELDS})
        r['iso_timestamp'] = (t0 + timedelta(seconds=i)).isoformat()
        r['compute_apps'] = []
        with contextlib.redirect_stdout(io.StringIO()):
            alerts = sw.ingest(adapt(r, residency_latency_ms=None), key=r.get('index', g)) or []
        for a in alerts:
            if not isinstance(a, dict):
                continue
            k = "%s %s" % (a.get('agent', '?'), a.get('type', '?'))
            gpus[k].add(g)
            raw[k] += 1
    return gpus, raw


def main():
    tmp = tempfile.mkdtemp(prefix='wd_swarm_requal_')
    os.makedirs(os.path.join(tmp, 'watchdog_data'))
    import repro_moe_multi_gpu as moe
    with contextlib.redirect_stdout(io.StringIO()):
        from watchdog import _PerGPUSwarm
    from intelligence.swarm.telemetry_adapter import adapt_row_to_swarm_telemetry
    from agent.telemetry import QUERY_FIELDS, parse_numeric_fields
    os.chdir(tmp)
    try:
        res = {sc: run(sc, moe, _PerGPUSwarm, adapt_row_to_swarm_telemetry,
                       QUERY_FIELDS, parse_numeric_fields) for sc, _ in SCENARIOS}
    finally:
        os.chdir(REPO)

    keys = sorted({k for sc, _ in SCENARIOS for k in res[sc][0]})
    print("SWARM ON NORMAL SERVING -- negative controls, SYNTHETIC, 8 GPUs x %d s each" % moe.STEPS)
    print("GPUs an agent fired on (of 8), raw alert count before dedup in brackets\n")
    print("%-58s %-10s %-10s %-10s" % ("agent / alert", "S1 steady", "S2 bursty", "S3 MoE"))
    for k in keys:
        cells = ["%d/8 (%d)" % (len(res[sc][0].get(k, ())), res[sc][1].get(k, 0)) for sc, _ in SCENARIOS]
        print("%-58s %-10s %-10s %-10s" % ((k[:58],) + tuple(cells)))
    if not keys:
        print("  no swarm alerts in any scenario")
    fp = [k for k in keys if any(res[sc][0].get(k) for sc, _ in SCENARIOS)]
    print("\nFALSE POSITIVES ON NORMAL SERVING: %s" % (", ".join(sorted({k.split()[0] for k in fp})) or "none"))
    print("Every agent not listed raised no alert in any scenario. Agents that need fields")
    print("nothing collects (CEI: agent2, agent5) cannot fire here -- untested, not passing.")
    print("In the live pipeline, GhostPowerPredictor alerts on GPUs with a model loaded are")
    print("reclassified to IDLE_RESIDENT_ENERGY (INFO) after this layer (commit 7abc65b).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
