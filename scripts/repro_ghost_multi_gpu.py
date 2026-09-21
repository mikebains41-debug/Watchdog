"""Reproduces two multi-GPU bugs in GhostPowerDetector (found 2026-09-21).
One detector instance keeps ONE baseline and ONE consecutive-hit counter
for every GPU fed to it. B: a GPU with no learned floor is judged against
another GPU's floor. C: a genuine ghost on one GPU is silenced when a clean
GPU's rows are interleaved, because they reset the shared counter."""
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

def fresh():
    p = DetectionPipeline(vram_strict=False)
    feed(p, [row(0, 78.4, 1)] * 40)
    return p

a = feed(fresh(), [row(0, 126.0, 1)] * 5)
b = feed(fresh(), [row(1, 126.0, 620)] * 5)
c = feed(fresh(), [r for _ in range(10) for r in (row(0, 78.4, 1), row(1, 126.0, 1))])
print("A positive control, one GPU      :", a or "none", "(expect alert)")
print("B GPU1 vs GPU0's floor           :", b or "none", "(BUG if alert)")
print("C real ghost on GPU1, GPU0 clean :", c or "none", "(BUG if none)")
