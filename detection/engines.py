import time, collections
from datetime import datetime
class GhostPowerDetector:
    def __init__(self, threshold_w=15.0, window=30):
        self.threshold_w = threshold_w
        self.baseline_w = None
        self.window = window
        self.history = collections.deque(maxlen=window)
    def update(self, row):
        power = float(row.get('power.draw',0))
        util = float(row.get('utilization.gpu',0))
        mem = float(row.get('memory.used',0))
        self.history.append({'power':power,'util':util,'mem':mem,'ts':row.get('iso_timestamp')})
        if len(self.history) < self.window: return None
        idle = [r['power'] for r in self.history if r['util']==0 and r['mem']<500]
        if not self.baseline_w and len(idle)>=10: self.baseline_w = sum(idle)/len(idle)
        if not self.baseline_w: return None
        if util==0 and power > self.baseline_w + self.threshold_w:
            delta = power - self.baseline_w
            return {'type':'GHOST_POWER','severity':'WARNING' if delta<50 else 'CRITICAL','gpu':row.get('index'),'power_w':power,'baseline_w':round(self.baseline_w,2),'delta_w':round(delta,2),'utilization':util,'timestamp':row.get('iso_timestamp'),'message':f"Ghost power {delta:.1f}W above baseline at 0% utilization"}
        return None
class VRAMResidualDetector:
    def __init__(self, residual_threshold_mb=100):
        self.threshold_mb = residual_threshold_mb
        self.pre_exit_mem = None
        self.last_util = None
    def update(self, row):
        util = float(row.get('utilization.gpu',0))
        mem = float(row.get('memory.used',0))
        if self.last_util and self.last_util > 10 and util == 0: self.pre_exit_mem = mem
        if self.pre_exit_mem and util==0 and mem > self.threshold_mb:
            alert = {'type':'VRAM_RESIDUAL','severity':'CRITICAL','gpu':row.get('index'),'memory_used_mb':mem,'threshold_mb':self.threshold_mb,'nvml_util_memory':row.get('utilization.memory',0),'timestamp':row.get('iso_timestamp'),'message':f"VRAM residual {mem:.0f}MB persists at 0% utilization. NVML blind: util.memory={row.get('utilization.memory')}%"}
            self.last_util = util
            return alert
        self.last_util = util
        return None
class PowerSideChannelDetector:
    def __init__(self, min_amplitude_w=5.0, window=200):
        self.min_amplitude = min_amplitude_w
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.last_alert = None
    def update(self, row):
        power = float(row.get('power.draw',0))
        self.history.append(power)
        if len(self.history) < self.window: return None
        vals = list(self.history)
        amplitude = max(vals)-min(vals)
        transitions = sum(1 for i in range(1,len(vals)) if abs(vals[i]-vals[i-1])>self.min_amplitude)
        if amplitude >= self.min_amplitude*2 and transitions > self.window*0.3:
            now = time.time()
            if self.last_alert and now-self.last_alert < 30: return None
            self.last_alert = now
            return {'type':'POWER_SIDE_CHANNEL','severity':'CRITICAL','gpu':row.get('index'),'amplitude_w':round(amplitude,2),'transitions':transitions,'timestamp':row.get('iso_timestamp'),'message':f"Power oscillation {amplitude:.1f}W — possible covert channel or workload fingerprinting"}
        return None
class ThermalEmanationDetector:
    def __init__(self, gradient_threshold=5.0, window=50):
        self.gradient_threshold = gradient_threshold
        self.window = window
        self.history = collections.deque(maxlen=window)
    def update(self, row):
        temp = float(row.get('temperature.gpu',0))
        util = float(row.get('utilization.gpu',0))
        self.history.append({'temp':temp,'util':util})
        if len(self.history) < 10: return None
        recent = list(self.history)[-10:]
        gradient = max(r['temp'] for r in recent) - min(r['temp'] for r in recent)
        if gradient > self.gradient_threshold and util < 10:
            return {'type':'THERMAL_EMANATION','severity':'WARNING','gpu':row.get('index'),'temp_gradient_c':round(gradient,2),'current_temp_c':temp,'utilization':util,'timestamp':row.get('iso_timestamp'),'message':f"Thermal gradient {gradient:.1f}C at {util:.0f}% util — possible thermal covert channel"}
        return None
class CrossTenantBleedingDetector:
    def __init__(self, bleed_threshold_w=20.0):
        self.bleed_threshold = bleed_threshold_w
        self.baseline_w = None
        self.baseline_samples = []
    def update(self, row):
        power = float(row.get('power.draw',0))
        util = float(row.get('utilization.gpu',0))
        mem = float(row.get('memory.used',0))
        if util==0 and mem<200 and len(self.baseline_samples)<100:
            self.baseline_samples.append(power)
            if len(self.baseline_samples)==100: self.baseline_w = sum(self.baseline_samples)/100
            return None
        if not self.baseline_w: return None
        if util==0 and mem<200 and power > self.baseline_w+self.bleed_threshold:
            delta = power-self.baseline_w
            return {'type':'CROSS_TENANT_BLEEDING','severity':'CRITICAL','gpu':row.get('index'),'power_w':power,'baseline_w':round(self.baseline_w,2),'delta_w':round(delta,2),'timestamp':row.get('iso_timestamp'),'message':f"Cross-tenant power bleed {delta:.1f}W — neighbor workload detected"}
        return None
class TimingCovertChannelDetector:
    def __init__(self, window=100, regularity_threshold=0.85):
        self.window = window
        self.regularity_threshold = regularity_threshold
        self.history = collections.deque(maxlen=window)
        self.last_alert = None
    def update(self, row):
        self.history.append(float(row.get('power.draw',0)))
        if len(self.history) < self.window: return None
        vals = list(self.history)
        transitions = [1 if vals[i]>vals[i-1] else -1 for i in range(1,len(vals))]
        reversals = sum(1 for i in range(1,len(transitions)) if transitions[i]!=transitions[i-1])
        regularity = reversals/len(transitions)
        if regularity > self.regularity_threshold:
            now = time.time()
            if self.last_alert and now-self.last_alert < 30: return None
            self.last_alert = now
            return {'type':'TIMING_COVERT_CHANNEL','severity':'CRITICAL','gpu':row.get('index'),'regularity_score':round(regularity,3),'timestamp':row.get('iso_timestamp'),'message':f"Regular power timing pattern (score={regularity:.3f}) — possible timing covert channel"}
        return None
class CrossWorkloadClusteringDetector:
    def __init__(self, correlation_window=300, min_gpus=2):
        self.correlation_window = correlation_window
        self.min_gpus = min_gpus
        self.gpu_events = {}
    def add_alert(self, alert):
        gpu = str(alert.get('gpu','unknown'))
        if gpu not in self.gpu_events: self.gpu_events[gpu] = []
        self.gpu_events[gpu].append({'type':alert['type'],'time':time.time()})
        return self._check_cluster()
    def _check_cluster(self):
        now = time.time()
        for gpu in self.gpu_events:
            self.gpu_events[gpu] = [e for e in self.gpu_events[gpu] if now-e['time']<self.correlation_window]
        active = [g for g in self.gpu_events if self.gpu_events[g]]
        if len(active) >= self.min_gpus:
            return {'type':'CROSS_WORKLOAD_CLUSTER','severity':'EMERGENCY','affected_gpus':active,'timestamp':datetime.now().isoformat(),'message':f"Correlated anomalies across {len(active)} GPUs — possible coordinated attack"}
        return None
class DetectionPipeline:
    def __init__(self, on_alert=None):
        self.on_alert = on_alert
        self.ghost_power = GhostPowerDetector()
        self.vram_residual = VRAMResidualDetector()
        self.power_side_channel = PowerSideChannelDetector()
        self.thermal = ThermalEmanationDetector()
        self.cross_tenant = CrossTenantBleedingDetector()
        self.timing = TimingCovertChannelDetector()
        self.clustering = CrossWorkloadClusteringDetector()
        self.alert_count = 0
    def process(self, row):
        for engine in [self.ghost_power,self.vram_residual,self.power_side_channel,self.thermal,self.cross_tenant,self.timing]:
            alert = engine.update(row)
            if alert:
                self.alert_count += 1
                cluster = self.clustering.add_alert(alert)
                self._emit(alert)
                if cluster: self._emit(cluster)
    def _emit(self, alert):
        print(f"[{alert['severity']}] {alert['type']} — {alert['message']}")
        if self.on_alert: self.on_alert(alert)
