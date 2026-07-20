import time, collections, subprocess
from datetime import datetime
from detection._shared import _EventState, _f


class CacheSideChannelDetector:
    def __init__(self, window=200):
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.last_alert = None
    def update(self, row):
        util_gpu = float(row.get('utilization.gpu',0))
        util_mem = float(row.get('utilization.memory',0))
        self.history.append({'util_gpu':util_gpu,'util_mem':util_mem})
        if len(self.history) < self.window: return None
        vals = list(self.history)
        mem_spikes = sum(1 for v in vals if v['util_mem'] > 50)
        avg_gpu = sum(v['util_gpu'] for v in vals)/len(vals)
        if mem_spikes > self.window*0.4 and avg_gpu < 15:
            now = time.time()
            if self.last_alert and now-self.last_alert < 60: return None
            self.last_alert = now
            return {'type':'CACHE_SIDE_CHANNEL','severity':'CRITICAL','gpu':row.get('index'),'mem_util_spikes':mem_spikes,'avg_gpu_util':round(avg_gpu,2),'timestamp':row.get('iso_timestamp'),'message':f"Memory spikes ({mem_spikes}/{self.window}) at avg {avg_gpu:.1f}% GPU — possible L2 cache side-channel"}
        return None


class MIGPartitionDesyncDetector:
    def __init__(self):
        self.last_alert = None
    def update(self, row):
        util_gpu = float(row.get('utilization.gpu',0))
        util_mem = float(row.get('utilization.memory',0))
        if util_gpu == 0 and util_mem > 40:
            now = time.time()
            if self.last_alert and now-self.last_alert < 60: return None
            self.last_alert = now
            try:
                r = subprocess.run(['nvidia-smi','mig','-lgip'],capture_output=True,text=True,timeout=5)
                mig_info = r.stdout.strip()[:200]
            except: mig_info = 'N/A'
            return {'type':'MIG_PARTITION_DESYNC','severity':'CRITICAL','gpu':row.get('index'),'gpu_util':util_gpu,'mem_util':util_mem,'mig_info':mig_info,'timestamp':row.get('iso_timestamp'),'message':f"MIG desync: GPU={util_gpu:.0f}% but mem controller={util_mem:.0f}% — cross-partition side channel"}
        return None


class SequentialVRAMReadDetector:
    """
    Detects high memory-bandwidth utilization covering a large fraction of
    VRAM while GPU compute utilization stays low -- consistent with bulk
    VRAM scraping (e.g. reading another tenant's residual model weights),
    but also indistinguishable from legitimate large-checkpoint loading.

    FIXED vs. original:
      - The original computed a `baseline_mem` from an active-use
        calibration phase but never referenced it anywhere in the firing
        condition -- dead code that looked like it was doing something.
        Removed entirely rather than left as decoration.
      - Was level-triggered via last_alert cooldown. Now edge-triggered
        via _EventState (require_consecutive=5).
      - float(row.get(...)) would crash on '[N/A]'. Now N/A-safe.
      - Default coverage threshold raised from 10% to 30% -- 10% of total
        VRAM is a small fraction to label "bulk" scraping. This default
        is still unvalidated against real hardware and should be tuned
        once real measurement data exists.

    STILL UNRESOLVED, stated rather than hidden: same discrimination gap
    as DMAAttackDetector -- cannot tell this apart from a legitimate large
    checkpoint or dataset load from telemetry alone.
    """

    def __init__(self, coverage_threshold_pct=30.0, util_mem_threshold=60.0,
                 util_gpu_ceiling=5.0, require_consecutive=5,
                 refire_after_s=60):
        self.coverage_threshold_pct = coverage_threshold_pct
        self.util_mem_threshold = util_mem_threshold
        self.util_gpu_ceiling = util_gpu_ceiling
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        mem_used = _f(row, 'memory.used')
        mem_total = _f(row, 'memory.total', default=1.0)
        util_gpu = _f(row, 'utilization.gpu')
        util_mem = _f(row, 'utilization.memory')
        if None in (mem_used, mem_total, util_gpu, util_mem) or mem_total <= 0:
            return None

        coverage_pct = (mem_used / mem_total) * 100

        condition = (util_mem > self.util_mem_threshold
                     and util_gpu < self.util_gpu_ceiling
                     and coverage_pct >= self.coverage_threshold_pct)
        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'SEQUENTIAL_VRAM_READ',
            'severity': 'EMERGENCY',
            'gpu': row.get('index'),
            'memory_used_mb': mem_used,
            'coverage_pct': round(coverage_pct, 2),
            'mem_util_pct': util_mem,
            'gpu_util_pct': util_gpu,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Bulk VRAM read pattern: {coverage_pct:.1f}% of VRAM "
                        f"at {util_mem:.0f}% mem bandwidth, {util_gpu:.0f}% "
                        f"compute -- possible exfiltration OR bulk data load "
                        f"(cannot be distinguished from telemetry alone)"),
        }
