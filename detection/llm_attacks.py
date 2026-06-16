import time, collections
from datetime import datetime
class InferencePowerFingerprintDetector:
    def __init__(self, deviation_threshold=0.25, calibration_samples=200):
        self.deviation_threshold = deviation_threshold
        self.calibration_samples = calibration_samples
        self.calibration = []
        self.baseline_mean = None
        self.baseline_std = None
        self.history = collections.deque(maxlen=100)
        self.last_alert = None
    def update(self, row):
        power = float(row.get('power.draw',0))
        util = float(row.get('utilization.gpu',0))
        if util < 10: return None
        if self.baseline_mean is None:
            if len(self.calibration) < self.calibration_samples: self.calibration.append(power); return None
            self.baseline_mean = sum(self.calibration)/len(self.calibration)
            variance = sum((p-self.baseline_mean)**2 for p in self.calibration)/len(self.calibration)
            self.baseline_std = variance**0.5
            return None
        self.history.append(power)
        if len(self.history) < 20: return None
        recent_mean = sum(list(self.history)[-20:])/20
        if self.baseline_std == 0: return None
        z_score = abs(recent_mean-self.baseline_mean)/self.baseline_std
        if z_score > self.deviation_threshold*10:
            now = time.time()
            if self.last_alert and now-self.last_alert < 60: return None
            self.last_alert = now
            return {'type':'INFERENCE_POWER_ANOMALY','severity':'CRITICAL','gpu':row.get('index'),'baseline_mean_w':round(self.baseline_mean,2),'current_mean_w':round(recent_mean,2),'z_score':round(z_score,3),'timestamp':row.get('iso_timestamp'),'message':f"Inference power deviation z={z_score:.2f} — model substitution or adversarial input"}
        return None
class AgentOrchestrationAnomalyDetector:
    def __init__(self, power_threshold=100, window=60):
        self.power_threshold = power_threshold
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.last_alert = None
    def update(self, row):
        power = float(row.get('power.draw',0))
        util = float(row.get('utilization.gpu',0))
        self.history.append({'power':power,'util':util})
        if len(self.history) < self.window: return None
        vals = list(self.history)
        overlap = sum(1 for v in vals if v['power'] > self.power_threshold and v['util'] < 10)
        if overlap > self.window*0.5:
            now = time.time()
            if self.last_alert and now-self.last_alert < 60: return None
            self.last_alert = now
            avg_power = sum(v['power'] for v in vals)/len(vals)
            avg_util = sum(v['util'] for v in vals)/len(vals)
            return {'type':'AGENT_ORCHESTRATION_ANOMALY','severity':'CRITICAL','gpu':row.get('index'),'avg_power_w':round(avg_power,2),'avg_util_pct':round(avg_util,2),'suspicious_samples':overlap,'timestamp':row.get('iso_timestamp'),'message':f"Agent claims idle ({avg_util:.1f}% util) but GPU draws {avg_power:.1f}W — covert mining or model extraction"}
        return None
class PromptInjectionSideEffectDetector:
    def __init__(self, spike_threshold=30, window=20):
        self.spike_threshold = spike_threshold
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.last_alert = None
    def update(self, row):
        power = float(row.get('power.draw',0))
        util = float(row.get('utilization.gpu',0))
        self.history.append({'power':power,'util':util})
        if len(self.history) < self.window: return None
        powers = [v['power'] for v in self.history]
        mean_power = sum(powers)/len(powers)
        max_spike = max(powers)-mean_power
        if max_spike > self.spike_threshold and util > 20:
            now = time.time()
            if self.last_alert and now-self.last_alert < 30: return None
            self.last_alert = now
            return {'type':'PROMPT_INJECTION_SIDEEFFECT','severity':'WARNING','gpu':row.get('index'),'power_spike_w':round(max_spike,2),'mean_power_w':round(mean_power,2),'timestamp':row.get('iso_timestamp'),'message':f"Inference power spike {max_spike:.1f}W above mean — possible adversarial prompt or jailbreak"}
        return None
