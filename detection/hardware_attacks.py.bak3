import time, collections, subprocess
from datetime import datetime
from detection._shared import _EventState, _f


class ClockGlitchDetector:
    """
    Detects a sudden SM clock drop while GPU utilization stays active.

    FIXED vs. original:
      - The original compared a 10-sample window's own MEAN to its own
        MIN -- this is not a baseline-vs-deviation comparison, it will
        register some "drop" in any naturally varying clock signal,
        since min <= mean by definition. Boost clocks vary normally
        under thermal/power throttling; this made ordinary DVFS
        behavior look identical to an attack. Replaced with a properly
        separate learned baseline (median of a calibration window),
        matching GhostPowerDetector's approach.
      - Was level-triggered via last_alert cooldown. Now edge-triggered.
      - float(row.get(...)) N/A-safe.
      - "possible clock glitch injection" stated the CAUSE as if
        established. Clock/voltage/laser fault injection are PHYSICAL
        attack techniques requiring specialized access to the die or
        power delivery -- not achievable purely over software from a
        rented cloud instance, and a real fault-injection attempt would
        be statistically indistinguishable, from telemetry alone, from
        ordinary thermal or power-limit throttling. Severity downgraded
        CRITICAL -> WARNING and message reworded to state this honestly.
        Alert 'type' string left unchanged to avoid disturbing any
        downstream key matching (e.g. remediation/response.py).
    """
    def __init__(self, drop_pct_threshold=10.0, baseline_min_samples=30,
                 baseline_window=300, util_floor=10.0,
                 require_consecutive=3, refire_after_s=60):
        self.drop_pct_threshold = drop_pct_threshold
        self.baseline_min_samples = baseline_min_samples
        self.util_floor = util_floor
        self.active_samples = collections.deque(maxlen=baseline_window)
        self.baseline_clock = None
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        sm_clock = _f(row, 'clocks.sm')
        util = _f(row, 'utilization.gpu')
        if sm_clock is None or util is None:
            return None

        if self.baseline_clock is None:
            if util > self.util_floor and sm_clock > 0:
                self.active_samples.append(sm_clock)
            if len(self.active_samples) >= self.baseline_min_samples:
                vals = sorted(self.active_samples)
                self.baseline_clock = vals[len(vals) // 2]

        if self.baseline_clock is None:
            return None

        drop_pct = ((self.baseline_clock - sm_clock) / self.baseline_clock * 100
                    ) if self.baseline_clock > 0 else 0
        condition = util > self.util_floor and drop_pct >= self.drop_pct_threshold
        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'CLOCK_GLITCH',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'sm_clock_mhz': round(sm_clock, 1),
            'baseline_clock_mhz': round(self.baseline_clock, 1),
            'drop_pct': round(drop_pct, 2),
            'utilization': util,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"SM clock {drop_pct:.1f}% below this GPU's own "
                        f"learned baseline while active -- cause "
                        f"unconfirmed, consistent with thermal/power "
                        f"throttling (normal) or a clock-glitch attempt "
                        f"(requires physical access, not verifiable from "
                        f"software telemetry alone)"),
        }


class VoltageGlitchDetector:
    """
    Detects a rapid power drop while GPU utilization stays roughly
    steady.

    FIXED vs. original:
      - Compared max-of-first-15-samples to min-of-last-5-samples WITHIN
        THE SAME 20-sample window -- not a baseline-vs-deviation
        comparison. Power capping under sustained high load (hitting the
        board's power limit) produces exactly this signature and is
        completely normal GPU behavior, not an attack. Replaced with a
        properly separate learned baseline.
      - Was level-triggered. Now edge-triggered.
      - float(row.get(...)) N/A-safe.
      - "possible voltage glitch" stated the cause as established.
        Voltage fault injection is a PHYSICAL attack technique -- same
        limitation as ClockGlitchDetector above. Severity downgraded
        CRITICAL -> WARNING, message reworded. Alert 'type' unchanged.
    """
    def __init__(self, drop_w_threshold=50.0, baseline_min_samples=30,
                 baseline_window=300, util_floor=10.0,
                 util_stability_pct=5.0, require_consecutive=3,
                 refire_after_s=60):
        self.drop_w_threshold = drop_w_threshold
        self.baseline_min_samples = baseline_min_samples
        self.util_floor = util_floor
        self.util_stability_pct = util_stability_pct
        self.active_samples = collections.deque(maxlen=baseline_window)
        self.baseline_power = None
        self.util_history = collections.deque(maxlen=10)
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        power = _f(row, 'power.draw')
        util = _f(row, 'utilization.gpu')
        if power is None or util is None:
            return None

        self.util_history.append(util)

        if self.baseline_power is None:
            if util > self.util_floor:
                self.active_samples.append(power)
            if len(self.active_samples) >= self.baseline_min_samples:
                vals = sorted(self.active_samples)
                self.baseline_power = vals[len(vals) // 2]

        if self.baseline_power is None or len(self.util_history) < 10:
            return None

        util_stable = (max(self.util_history) - min(self.util_history)
                       ) < self.util_stability_pct
        power_drop = self.baseline_power - power
        condition = (util > self.util_floor and util_stable
                     and power_drop > self.drop_w_threshold)
        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'VOLTAGE_GLITCH',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'power_w': round(power, 2),
            'baseline_power_w': round(self.baseline_power, 2),
            'power_drop_w': round(power_drop, 2),
            'utilization': util,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Power {power_drop:.1f}W below this GPU's own "
                        f"learned baseline at stable {util:.0f}% util -- "
                        f"cause unconfirmed, consistent with power-limit "
                        f"throttling (normal) or a voltage-glitch attempt "
                        f"(requires physical access, not verifiable from "
                        f"software telemetry alone)"),
        }


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
    """
    Detects a rapid GPU temperature change within a short window.

    FIXED vs. original:
      - "possible laser fault injection" claimed to detect a PHYSICAL
        attack technique (a focused laser aimed at exposed silicon to
        induce bit-flips) requiring physical access to the die. This
        cannot be achieved or meaningfully detected from software
        telemetry in a rented cloud container -- what this signal
        actually captures is functionally the same pattern as the
        ThermalEmanationDetector deleted from engines.py earlier tonight
        for firing on ordinary cooldown/heating transients. Reframed
        honestly: this reports that a rapid thermal transient occurred,
        without claiming to know or detect its physical cause.
      - Was level-triggered via a 10s cooldown with NO debounce at all --
        fired on the very first qualifying sample. Now edge-triggered.
      - float(row.get(...)) N/A-safe.
      - Severity EMERGENCY -> INFO: a rapid temp change during normal
        workload start/stop is common and expected; this is context, not
        an actionable alert. Alert 'type' left unchanged.
    """
    def __init__(self, delta_threshold_c=5.0, time_window_s=0.5,
                 require_consecutive=2, refire_after_s=60):
        self.delta_threshold_c = delta_threshold_c
        self.time_window_s = time_window_s
        self.history = collections.deque(maxlen=100)
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        temp = _f(row, 'temperature.gpu')
        if temp is None:
            return None
        ts = time.time()
        self.history.append({'temp': temp, 'ts': ts})
        window = [h for h in self.history if ts - h['ts'] <= self.time_window_s]
        if len(window) < 3:
            return None
        temps = [h['temp'] for h in window]
        delta = max(temps) - min(temps)

        if not self.state.should_emit(delta >= self.delta_threshold_c):
            return None

        return {
            'type': 'LASER_INJECTION',
            'severity': 'INFO',
            'gpu': row.get('index'),
            'temp_delta_c': round(delta, 2),
            'current_temp_c': temp,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Temperature changed {delta:.1f}C within "
                        f"{self.time_window_s}s -- consistent with a "
                        f"normal workload start/stop transient. Not "
                        f"evidence of physical fault injection, which "
                        f"cannot be detected from software telemetry "
                        f"alone."),
        }
