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

class AgentSessionVRAMRetentionDetector:
    """
    Detects VRAM retention after agentic AI session ends.
    Directly applies CVE 2048350 to the agentic AI threat model.
    Proprietary molecular/drug discovery data sitting in VRAM post-session.
    """
    def __init__(self, retention_threshold_mb=100, idle_window=30):
        self.retention_threshold_mb = retention_threshold_mb
        self.idle_window = idle_window
        self.history = collections.deque(maxlen=idle_window)
        self.session_active = False
        self.session_peak_mem = 0
        self.last_alert = None

    def update(self, row):
        util = float(row.get('utilization.gpu', 0))
        mem = float(row.get('memory.used', 0))
        self.history.append({'util': util, 'mem': mem})

        if util > 10:
            self.session_active = True
            self.session_peak_mem = max(self.session_peak_mem, mem)
            return None

        if self.session_active and util == 0:
            if len(self.history) < self.idle_window:
                return None
            recent = list(self.history)
            all_idle = all(r['util'] == 0 for r in recent[-10:])
            if all_idle and mem > self.retention_threshold_mb:
                now = time.time()
                if self.last_alert and now - self.last_alert < 60:
                    return None
                self.last_alert = now
                self.session_active = False
                return {
                    'type': 'AGENT_VRAM_RETENTION',
                    'severity': 'CRITICAL',
                    'gpu': row.get('index'),
                    'retained_mb': round(mem, 2),
                    'session_peak_mb': round(self.session_peak_mem, 2),
                    'threshold_mb': self.retention_threshold_mb,
                    'nvml_util': util,
                    'timestamp': row.get('iso_timestamp'),
                    'message': f"Agent session ended but {mem:.0f}MB VRAM retained — CVE-2048350 — proprietary data exposure risk"
                }
        return None


class InterAgentHandoffAnomalyDetector:
    """
    Detects anomalous power transitions between agent-to-agent handoffs.
    Watches for compromised upstream agent passing malicious payload to downstream agent.
    Baseline: normal inter-call power drop. Alert: downstream agent resumes with abnormal power.
    """
    def __init__(self, baseline_samples=50, spike_threshold_w=40, window=20):
        self.baseline_samples = baseline_samples
        self.spike_threshold = spike_threshold_w
        self.window = window
        self.handoff_baselines = []
        self.baseline_mean = None
        self.prev_util = None
        self.handoff_detected = False
        self.post_handoff_buffer = collections.deque(maxlen=window)
        self.last_alert = None

    def update(self, row):
        util = float(row.get('utilization.gpu', 0))
        power = float(row.get('power.draw', 0))

        # Detect handoff: util drops to 0 then resumes
        if self.prev_util is not None:
            if self.prev_util > 10 and util == 0:
                # Agent going idle — record handoff power
                self.handoff_detected = True
                self.post_handoff_buffer.clear()
                if self.baseline_mean is None and len(self.handoff_baselines) < self.baseline_samples:
                    self.handoff_baselines.append(power)
                    if len(self.handoff_baselines) == self.baseline_samples:
                        self.baseline_mean = sum(self.handoff_baselines) / len(self.handoff_baselines)

            if self.handoff_detected and util > 10:
                # Agent resuming after handoff
                self.post_handoff_buffer.append(power)
                if len(self.post_handoff_buffer) >= 10 and self.baseline_mean is not None:
                    resume_mean = sum(list(self.post_handoff_buffer)[:10]) / 10
                    delta = resume_mean - self.baseline_mean
                    if delta > self.spike_threshold:
                        now = time.time()
                        if self.last_alert and now - self.last_alert < 60:
                            self.prev_util = util
                            return None
                        self.last_alert = now
                        self.handoff_detected = False
                        self.prev_util = util
                        return {
                            'type': 'INTER_AGENT_HANDOFF_ANOMALY',
                            'severity': 'CRITICAL',
                            'gpu': row.get('index'),
                            'baseline_power_w': round(self.baseline_mean, 2),
                            'resume_power_w': round(resume_mean, 2),
                            'delta_w': round(delta, 2),
                            'timestamp': row.get('iso_timestamp'),
                            'message': f"Agent resume power {resume_mean:.1f}W vs baseline {self.baseline_mean:.1f}W (+{delta:.1f}W) — possible malicious payload from upstream agent"
                        }
                    self.handoff_detected = False

        self.prev_util = util
        return None
