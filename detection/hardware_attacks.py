import time, collections, subprocess
from datetime import datetime
class ClockGlitchDetector:
    def __init__(self, deviation_pct=10.0, window=50):
        self.deviation_pct = deviation_pct
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.last_alert = None
    def update(self, row):
        sm_clock = float(row.get('clocks.sm',0))
        util = float(row.get('utilization.gpu',0))
        self.history.append({'sm':sm_clock,'util':util})
        if len(self.history) < 10: return None
        recent = list(self.history)[-10:]
        sm_vals = [r['sm'] for r in recent if r['sm'] > 0]
        if len(sm_vals) < 5: return None
        sm_mean = sum(sm_vals)/len(sm_vals)
        sm_drop = sm_mean - min(sm_vals)
        drop_pct = (sm_drop/sm_mean*100) if sm_mean > 0 else 0
        if drop_pct >= self.deviation_pct and util > 10:
            now = time.time()
            if self.last_alert and now-self.last_alert < 30: return None
            self.last_alert = now
            return {'type':'CLOCK_GLITCH','severity':'CRITICAL','gpu':row.get('index'),'sm_clock_mean':round(sm_mean,1),'drop_pct':round(drop_pct,2),'timestamp':row.get('iso_timestamp'),'message':f"Clock drop {drop_pct:.1f}% at {util:.0f}% util — possible clock glitch injection"}
        return None
class VoltageGlitchDetector:
    def __init__(self, window=100):
        self.window = window
        self.power_history = collections.deque(maxlen=window)
        self.last_alert = None
    def update(self, row):
        power = float(row.get('power.draw',0))
        util = float(row.get('utilization.gpu',0))
        self.power_history.append({'power':power,'util':util})
        if len(self.power_history) < self.window: return None
        vals = list(self.power_history)
        powers = [v['power'] for v in vals[-20:]]
        utils = [v['util'] for v in vals[-20:]]
        power_drop = max(powers[:-5])-min(powers[-5:]) if len(powers)>=10 else 0
        util_stable = max(utils)-min(utils) < 5
        if power_drop > 50 and util_stable and util > 10:
            now = time.time()
            if self.last_alert and now-self.last_alert < 30: return None
            self.last_alert = now
            return {'type':'VOLTAGE_GLITCH','severity':'CRITICAL','gpu':row.get('index'),'power_drop_w':round(power_drop,2),'utilization':util,'timestamp':row.get('iso_timestamp'),'message':f"Power droop {power_drop:.1f}W at stable {util:.0f}% util — possible voltage glitch"}
        return None
class DMAAttackDetector:
    def __init__(self):
        self.baseline_mem = None
        self.samples = []
        self.last_alert = None
    def update(self, row):
        mem_used = float(row.get('memory.used',0))
        util = float(row.get('utilization.gpu',0))
        util_mem = float(row.get('utilization.memory',0))
        if self.baseline_mem is None:
            if util == 0 and len(self.samples) < 50: self.samples.append(mem_used)
            elif len(self.samples) >= 50: self.baseline_mem = sum(self.samples)/len(self.samples)
            return None
        if util == 0 and util_mem > 30 and mem_used > self.baseline_mem+100:
            now = time.time()
            if self.last_alert and now-self.last_alert < 60: return None
            self.last_alert = now
            return {'type':'DMA_ATTACK','severity':'EMERGENCY','gpu':row.get('index'),'memory_used_mb':mem_used,'memory_util_pct':util_mem,'gpu_util_pct':util,'timestamp':row.get('iso_timestamp'),'message':f"Memory bandwidth {util_mem:.0f}% at 0% GPU compute — possible DMA attack"}
        return None
class LaserInjectionDetector:
    def __init__(self, delta_threshold=5.0, time_window_s=0.5):
        self.delta_threshold = delta_threshold
        self.time_window_s = time_window_s
        self.history = collections.deque(maxlen=100)
        self.last_alert = None
    def update(self, row):
        temp = float(row.get('temperature.gpu',0))
        ts = time.time()
        self.history.append({'temp':temp,'ts':ts})
        if len(self.history) < 5: return None
        window = [h for h in self.history if ts-h['ts'] <= self.time_window_s]
        if len(window) < 3: return None
        temps = [h['temp'] for h in window]
        delta = max(temps)-min(temps)
        if delta >= self.delta_threshold:
            now = time.time()
            if self.last_alert and now-self.last_alert < 10: return None
            self.last_alert = now
            return {'type':'LASER_INJECTION','severity':'EMERGENCY','gpu':row.get('index'),'temp_delta_c':round(delta,2),'current_temp_c':temp,'timestamp':row.get('iso_timestamp'),'message':f"Temp spike {delta:.1f}C in {self.time_window_s}s — possible laser fault injection"}
        return None
