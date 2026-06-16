import time, collections, subprocess
from datetime import datetime
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
    def __init__(self, read_threshold_pct=10.0, window=50):
        self.read_threshold_pct = read_threshold_pct
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.baseline_mem = None
        self.baseline_samples = []
        self.last_alert = None
    def update(self, row):
        mem_used = float(row.get('memory.used',0))
        mem_total = float(row.get('memory.total',1))
        util_gpu = float(row.get('utilization.gpu',0))
        util_mem = float(row.get('utilization.memory',0))
        if self.baseline_mem is None and util_gpu > 10:
            self.baseline_samples.append(mem_used)
            if len(self.baseline_samples) >= 20: self.baseline_mem = max(self.baseline_samples)
            return None
        if self.baseline_mem is None: return None
        self.history.append({'util_gpu':util_gpu,'util_mem':util_mem,'mem':mem_used})
        if len(self.history) < 10: return None
        recent = list(self.history)[-10:]
        avg_util_mem = sum(r['util_mem'] for r in recent)/len(recent)
        avg_util_gpu = sum(r['util_gpu'] for r in recent)/len(recent)
        coverage_pct = (mem_used/mem_total*100) if mem_total > 0 else 0
        if avg_util_mem > 60 and avg_util_gpu < 5 and coverage_pct >= self.read_threshold_pct:
            now = time.time()
            if self.last_alert and now-self.last_alert < 60: return None
            self.last_alert = now
            return {'type':'SEQUENTIAL_VRAM_READ','severity':'EMERGENCY','gpu':row.get('index'),'memory_used_mb':mem_used,'coverage_pct':round(coverage_pct,2),'avg_mem_util':round(avg_util_mem,2),'avg_gpu_util':round(avg_util_gpu,2),'timestamp':row.get('iso_timestamp'),'message':f"Bulk VRAM read {coverage_pct:.1f}% at {avg_util_mem:.0f}% mem BW — model exfiltration"}
        return None
