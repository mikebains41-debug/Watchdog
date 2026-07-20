import time, collections, subprocess
from datetime import datetime
from detection._shared import _EventState, _f


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
    """
    Detects memory-bandwidth activity at 0% GPU compute -- consistent with
    a DMA-based data exfiltration attack, but also indistinguishable from
    ordinary checkpoint/dataset loading into VRAM before compute starts.

    FIXED vs. original:
      - Baseline was the MEAN of up to 50 idle samples -- a single
        contaminated sample during calibration could skew it. Now MEDIAN,
        matching GhostPowerDetector's approach, and recomputed
        continuously from a rolling window rather than frozen after one
        calibration pass.
      - Was level-triggered via a raw last_alert timestamp cooldown --
        fired on the first qualifying sample, then just rate-limited.
        Now edge-triggered via _EventState (require_consecutive=5), so a
        sustained pattern is required, not one sample.
      - float(row.get(...)) would crash (ValueError) on nvidia-smi's
        '[N/A]' strings for unsupported fields. Now uses the N/A-safe
        parser from detection._shared.

    STILL UNRESOLVED, stated rather than hidden:
      This detector cannot distinguish a DMA attack from legitimate bulk
      data loading. That requires a signal it does not have access to --
      e.g. correlating with process start/stop events. Until that exists,
      treat the EMERGENCY / kill_process mapping on this alert type
      (see remediation/response.py) as unvalidated, not a settled design.
    """

    def __init__(self, mem_delta_threshold_mb=100, util_mem_threshold=30.0,
                 baseline_min_samples=30, baseline_window=200,
                 require_consecutive=5, refire_after_s=60):
        self.mem_delta_threshold_mb = mem_delta_threshold_mb
        self.util_mem_threshold = util_mem_threshold
        self.baseline_min_samples = baseline_min_samples
        self.idle_samples = collections.deque(maxlen=baseline_window)
        self.baseline_mem = None
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        mem_used = _f(row, 'memory.used')
        util = _f(row, 'utilization.gpu')
        util_mem = _f(row, 'utilization.memory')
        if mem_used is None or util is None or util_mem is None:
            return None

        # FIXED: freeze baseline_mem once established, same reasoning as
        # GhostPowerDetector -- see that class's docstring. This one was
        # worse before the fix: baseline inclusion only required util==0,
        # with no secondary gate, so a sustained DMA exfiltration event
        # (util==0, mem_used elevated) fed directly into its own baseline
        # with nothing else in the way.
        if self.baseline_mem is None:
            if util == 0:
                self.idle_samples.append(mem_used)
            if len(self.idle_samples) >= self.baseline_min_samples:
                vals = sorted(self.idle_samples)
                self.baseline_mem = vals[len(vals) // 2]

        if self.baseline_mem is None:
            return None

        condition = (util == 0 and util_mem > self.util_mem_threshold
                     and mem_used > self.baseline_mem + self.mem_delta_threshold_mb)
        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'DMA_ATTACK',
            'severity': 'EMERGENCY',
            'gpu': row.get('index'),
            'memory_used_mb': mem_used,
            'baseline_mem_mb': round(self.baseline_mem, 1),
            'memory_util_pct': util_mem,
            'gpu_util_pct': util,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Memory bandwidth {util_mem:.0f}% at 0% GPU compute, "
                        f"sustained -- possible DMA attack OR bulk data load "
                        f"(cannot be distinguished from telemetry alone)"),
        }


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
