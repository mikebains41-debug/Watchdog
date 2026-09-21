"""Cluster-action target validation, 2026-09-21. Before this fix, a null/empty/
malformed target was passed straight to kubectl/scancel/nvidia-smi -- so
slurm_evict_job(None) built `scancel None` and, on a real controller, ran it.
After: refused before any subprocess runs. Bad targets must all say
REFUSED_NO_TARGET; valid targets reach the tool (which reports it missing here)."""
import sys; sys.path.insert(0, '.')
from orchestration.cluster_actions import ClusterOrchestration
c = ClusterOrchestration()
bad = [
    ("slurm_evict_job(None)",        lambda: c.slurm_evict_job(None)),
    ("slurm_evict_job('')",          lambda: c.slurm_evict_job('')),
    ("slurm_evict_job('None')",      lambda: c.slurm_evict_job('None')),
    ("slurm_evict_job('abc')",       lambda: c.slurm_evict_job('abc')),
    ("kubernetes_taint(None)",       lambda: c.kubernetes_taint(None)),
    ("kubernetes_taint('a b')",      lambda: c.kubernetes_taint('a b')),
    ("nvlink_disable(0, None)",      lambda: c.nvlink_disable(0, None)),
    ("nvlink_disable(None, 3)",      lambda: c.nvlink_disable(None, 3)),
]
good = [
    ("slurm_evict_job(99999)",       lambda: c.slurm_evict_job(99999)),
    ("kubernetes_taint('node-1')",   lambda: c.kubernetes_taint('node-1')),
    ("nvlink_disable(0, 3)",         lambda: c.nvlink_disable(0, 3)),
]
ran = 0
print("BAD TARGETS (must all be REFUSED):")
for label, fn in bad:
    r = fn()
    ok = r.startswith('REFUSED_NO_TARGET')
    if not ok: ran += 1
    print("  %-28s -> %s" % (label, r[:55]))
print("VALID TARGETS (reach the tool; tool missing here is fine):")
for label, fn in good:
    r = fn()
    wrongly_refused = r.startswith('REFUSED_NO_TARGET')
    if wrongly_refused: ran += 1
    print("  %-28s -> %s" % (label, r[:55]))
print("\nVERDICT:", "PASS -- every bad target refused before subprocess, valid ones not"
      if ran == 0 else "FAIL (%d wrong)" % ran)
