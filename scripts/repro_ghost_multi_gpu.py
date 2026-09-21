"""Multi-GPU GhostPowerDetector behaviour (found 2026-09-21).
Before the PerGPU fix, one detector instance kept ONE floor and ONE
consecutive-hit counter for all GPUs.
  B: GPU with no floor of its own judged against another GPU's floor.
  C: GPU ghosting from its very first sample. No detector can learn a clean
     floor from ghost rows; needs a seeded floor (per-model profile).
  D: both GPUs start cold, then GPU1 ghosts while GPU0 stays clean.
     The real bug: before the fix, GPU0's clean rows reset the shared
     counter and the genuine ghost on GPU1 was never reported."""
import sys; sys.path.insert(0, '.')
from detection.engines import DetectionPipeline

def row(i, w, m):
    return {'index': i, 'uuid': 'GPU-%d' % i, 'power.draw': w, 'utilization.gpu': 0,
            'memory.used': m, 'iso_timestamp': '2026-09-21T00:00:00', 'compute_apps': []}

def feed(p, rows):
    out = []
    for r in rows:
        res = p.process(r) or []
        out += [(a.get('gpu'), a.get('delta_w')) for a in res
                if isinstance(a, dict) and a.get('type') == 'GHOST_POWER']
    return out

def gpu0_cold():
    p = DetectionPipeline(vram_strict=False)
    feed(p, [row(0, 78.4, 1)] * 40)
    return p

def both_cold():
    p = DetectionPipeline(vram_strict=False)
    feed(p, [r for _ in range(40) for r in (row(0, 78.4, 1), row(1, 78.4, 1))])
    return p

pairs = lambda a, b, n=10: [r for _ in range(n) for r in (a, b)]
a = feed(gpu0_cold(), [row(0, 126.0, 1)] * 5)
b = feed(gpu0_cold(), [row(1, 126.0, 620)] * 5)
c = feed(gpu0_cold(), pairs(row(0, 78.4, 1), row(1, 126.0, 1)))
d = feed(both_cold(), pairs(row(0, 78.4, 1), row(1, 126.0, 1)))
print("A positive control, one GPU          :", a or "none", "(expect alert)")
print("B GPU1 no floor, vs GPU0's floor     :", b or "none", "(fixed: none)")
print("C GPU1 ghosting from first sample    :", c or "none", "(none: needs seeded floor)")
print("D both cold, then GPU1 ghosts        :", d or "none", "(THE BUG: must alert on GPU 1)")
