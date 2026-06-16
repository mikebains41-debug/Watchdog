import time, collections, hashlib, subprocess
from datetime import datetime
class RowhammerProxyDetector:
    def __init__(self, activation_threshold=1000000, window=50):
        self.threshold = activation_threshold
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.last_alert = None
    def update(self, row):
        mem_used = float(row.get('memory.used',0))
        util = float(row.get('utilization.gpu',0))
        self.history.append({'mem':mem_used,'util':util,'ts':row.get('iso_timestamp')})
        if len(self.history) < self.window: return None
        mem_vals = [r['mem'] for r in self.history]
        mem_variance = max(mem_vals) - min(mem_vals)
        low_util_high_mem = [r for r in self.history if r['util'] < 5 and r['mem'] > 500]
        if len(low_util_high_mem) > self.window * 0.6 and mem_variance > 100:
            now = time.time()
            if self.last_alert and now - self.last_alert < 60: return None
            self.last_alert = now
            return {'type':'ROWHAMMER_PROXY','severity':'WARNING','gpu':row.get('index'),'mem_variance_mb':round(mem_variance,2),'low_util_high_mem_samples':len(low_util_high_mem),'timestamp':row.get('iso_timestamp'),'message':f"High memory activation at low utilization — possible rowhammer probe (variance={mem_variance:.0f}MB)"}
        return None
class ModelMutationDetector:
    def __init__(self, check_interval=300):
        self.check_interval = check_interval
        self.checksums = {}
        self.last_check = {}
    def compute_vram_checksum(self, gpu_index=0):
        try:
            import torch
            if not torch.cuda.is_available(): return None
            probe = torch.empty(1024*1024, dtype=torch.float32, device=f'cuda:{gpu_index}')
            sample = probe[:10000].cpu().numpy().tobytes()
            del probe
            return hashlib.sha256(sample).hexdigest()
        except: return None
    def check(self, gpu_index=0):
        now = time.time()
        last = self.last_check.get(gpu_index, 0)
        if now - last < self.check_interval: return None
        self.last_check[gpu_index] = now
        checksum = self.compute_vram_checksum(gpu_index)
        if checksum is None: return None
        if gpu_index in self.checksums and self.checksums[gpu_index] != checksum:
            alert = {'type':'MODEL_MUTATION','severity':'CRITICAL','gpu':gpu_index,'prev_checksum':self.checksums[gpu_index][:16]+'...','curr_checksum':checksum[:16]+'...','timestamp':datetime.now().isoformat(),'message':f"VRAM content changed between checks — possible model tampering or backdoor injection"}
            self.checksums[gpu_index] = checksum
            return alert
        self.checksums[gpu_index] = checksum
        return None
class PerfCounterSideChannelDetector:
    """CVE-2018-6260: performance counter side-channel detection."""
    def __init__(self, window=100):
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.last_alert = None
    def update(self, row):
        util_gpu = float(row.get('utilization.gpu',0))
        util_mem = float(row.get('utilization.memory',0))
        power = float(row.get('power.draw',0))
        self.history.append({'util_gpu':util_gpu,'util_mem':util_mem,'power':power})
        if len(self.history) < self.window: return None
        vals = list(self.history)
        gpu_utils = [r['util_gpu'] for r in vals]
        mem_utils = [r['util_mem'] for r in vals]
        gpu_variance = max(gpu_utils) - min(gpu_utils)
        mem_variance = max(mem_utils) - min(mem_utils)
        if util_gpu < 5 and mem_variance > 20 and gpu_variance < 5:
            now = time.time()
            if self.last_alert and now - self.last_alert < 60: return None
            self.last_alert = now
            return {'type':'PERF_COUNTER_SIDE_CHANNEL','severity':'CRITICAL','gpu':row.get('index'),'util_gpu':util_gpu,'mem_util_variance':round(mem_variance,2),'timestamp':row.get('iso_timestamp'),'message':f"Memory utilization variance {mem_variance:.1f}% at {util_gpu:.0f}% GPU util — possible CVE-2018-6260 performance counter side-channel"}
        return None
class NVLinkFabricDetector:
    def __init__(self, window=50):
        self.window = window
        self.history = collections.deque(maxlen=window)
    def sample(self):
        try:
            r = subprocess.run(['nvidia-smi','nvlink','--status'],capture_output=True,text=True,timeout=5)
            return r.stdout.strip()
        except: return None
    def update(self, row):
        status = self.sample()
        if not status: return None
        if 'inactive' in status.lower() or 'error' in status.lower():
            return {'type':'NVLINK_ANOMALY','severity':'WARNING','gpu':row.get('index'),'timestamp':row.get('iso_timestamp'),'message':f"NVLink fabric anomaly detected — possible link disable or man-in-the-middle on interconnect"}
        return None
class SupplyChainDetector:
    def __init__(self, expected_efficiency_flops_per_watt=None):
        self.baseline_set = False
        self.baseline_power = None
        self.baseline_perf = None
        self.checked = False
    def check_counterfeit(self, row):
        if self.checked: return None
        power = float(row.get('power.draw',0))
        util = float(row.get('utilization.gpu',0))
        name = row.get('name','')
        if util < 1 or power < 10: return None
        self.checked = True
        expected = {'H200':700,'B200':1000,'H100':700,'A100':400}
        expected_power = None
        for gpu, ep in expected.items():
            if gpu in name: expected_power = ep; break
        if expected_power and power > expected_power * 1.15:
            return {'type':'SUPPLY_CHAIN_ANOMALY','severity':'WARNING','gpu':row.get('index'),'name':name,'power_w':power,'expected_max_w':expected_power,'timestamp':row.get('iso_timestamp'),'message':f"Power draw {power:.0f}W exceeds expected {expected_power}W for {name} — possible counterfeit or tampered device"}
        return None
