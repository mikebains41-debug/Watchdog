"""
Watchdog detection engines.

Design rules enforced here:
  1. Edge-triggered, not level-triggered. An alert fires when a condition
     STARTS, not on every sample while it persists. Level-triggered alerting
     is what turns a 10-minute event into 600 CRITICALs.
  2. No detector fires on a state documented as architecturally normal
     (cooldown tails, coordinated multi-GPU bursts, idle floor).
  3. A detector that cannot see its subject in the input does not ship.
     VRAMResidualDetector requires per-process data and says so loudly
     rather than approximating.

Deleted vs. previous version, deliberately:
  - CrossTenantBleedingDetector: duplicate of GhostPowerDetector. Neighbour
    workload is not inferable from own-GPU power draw.
  - ThermalEmanationDetector: fired on every cooldown, which is normal.
  - CrossWorkloadClustering promoted from EMERGENCY to INFO: coordinated
    bursts across GPUs are documented architectural behaviour, not attack.
"""

import time
import collections
from datetime import datetime


# --------------------------------------------------------------------------
# Shared: edge-triggered event state
# --------------------------------------------------------------------------

class _EventState:
    """Turns a per-sample boolean into start/stop events.

    require_consecutive: samples the condition must hold before firing.
        Debounces single-sample spikes.
    refire_after_s: if the condition stays true this long, re-emit once.
        Set to None to alert exactly once per episode.
    """

    def __init__(self, require_consecutive=3, refire_after_s=300):
        self.require_consecutive = require_consecutive
        self.refire_after_s = refire_after_s
        self._streak = 0
        self._active = False
        self._last_emit = None

    def should_emit(self, condition_met, now=None):
        now = time.time() if now is None else now

        if not condition_met:
            self._streak = 0
            self._active = False
            return False

        self._streak += 1
        if self._streak < self.require_consecutive:
            return False

        if not self._active:
            self._active = True
            self._last_emit = now
            return True

        if self.refire_after_s and (now - self._last_emit) >= self.refire_after_s:
            self._last_emit = now
            return True

        return False

    @property
    def active(self):
        return self._active


def _f(row, key, default=0.0):
    """nvidia-smi emits '[N/A]' and '' for unsupported fields. Treat as absent."""
    v = row.get(key, default)
    if v is None:
        return None
    s = str(v).strip()
    if s == '' or s.startswith('[') or s.lower() in ('n/a', 'na', 'unknown'):
        return None
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# 1. Ghost power
# --------------------------------------------------------------------------

class GhostPowerDetector:
    """Power draw materially above the idle floor while NVML reports 0% util.

    Baseline is the median of observed idle samples, not the mean: a single
    ghost-power event contaminating the baseline window would otherwise raise
    the floor and mask the very thing being detected.
    """

    def __init__(self, threshold_w=15.0, baseline_min_samples=30,
                 baseline_window=600, idle_mem_mb=500):
        self.threshold_w = threshold_w
        self.baseline_min_samples = baseline_min_samples
        self.idle_mem_mb = idle_mem_mb
        self.idle_samples = collections.deque(maxlen=baseline_window)
        self.baseline_w = None
        self.state = _EventState(require_consecutive=3, refire_after_s=300)

    def _update_baseline(self, power, util, mem):
        # Only genuinely quiescent samples inform the floor.
        if util == 0 and mem is not None and mem < self.idle_mem_mb:
            self.idle_samples.append(power)
        if len(self.idle_samples) >= self.baseline_min_samples:
            vals = sorted(self.idle_samples)
            self.baseline_w = vals[len(vals) // 2]

    def update(self, row):
        power = _f(row, 'power.draw')
        util = _f(row, 'utilization.gpu')
        mem = _f(row, 'memory.used')
        if power is None or util is None:
            return None

        self._update_baseline(power, util, mem)
        if self.baseline_w is None:
            return None  # still learning the floor

        delta = power - self.baseline_w
        condition = (util == 0 and delta > self.threshold_w)

        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'GHOST_POWER',
            'severity': 'WARNING' if delta < 50 else 'CRITICAL',
            'gpu': row.get('index'),
            'power_w': round(power, 2),
            'baseline_w': round(self.baseline_w, 2),
            'delta_w': round(delta, 2),
            'baseline_samples': len(self.idle_samples),
            'utilization': util,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Ghost power {delta:.1f}W above {self.baseline_w:.1f}W "
                        f"idle floor at 0% utilization"),
        }


# --------------------------------------------------------------------------
# 2. VRAM residual  (requires per-process telemetry)
# --------------------------------------------------------------------------

class VRAMResidualUnavailable(RuntimeError):
    """Raised when per-process data is absent. Deliberately not swallowed."""


class VRAMResidualDetector:
    """Memory still allocated after the owning process is gone.

    The finding this detects is: VRAM remains readable after a GRACEFUL
    process exit, and is only reclaimed by SIGKILL. That is a statement
    about processes. It cannot be made from aggregate memory.used alone --
    a resident idle model looks identical to residual memory.

    Requires row['compute_apps'] as a list of {'pid': int, 'used_memory': mb},
    from:  nvidia-smi --query-compute-apps=pid,used_memory --format=csv,noheader,nounits

    If that key is absent, this raises. It does not guess.
    """

    def __init__(self, residual_threshold_mb=100, grace_samples=2, strict=True):
        self.threshold_mb = residual_threshold_mb
        self.grace_samples = grace_samples
        self.strict = strict
        self.known_pids = {}          # pid -> last observed used_memory
        self.pending = {}             # pid -> samples since disappearance
        self.state = _EventState(require_consecutive=1, refire_after_s=None)

    def update(self, row):
        apps = row.get('compute_apps')
        if apps is None:
            if self.strict:
                raise VRAMResidualUnavailable(
                    "VRAMResidualDetector requires row['compute_apps']. "
                    "Aggregate memory.used cannot distinguish residual memory "
                    "from a resident model. Add --query-compute-apps to the "
                    "collector or construct with strict=False to disable."
                )
            return None

        mem_total_used = _f(row, 'memory.used')
        current = {int(a['pid']): float(a['used_memory']) for a in apps}

        # Processes that vanished since last sample.
        for pid, last_mem in list(self.known_pids.items()):
            if pid not in current:
                self.pending.setdefault(pid, {'samples': 0, 'mem_at_exit': last_mem})

        alert = None
        for pid, info in list(self.pending.items()):
            info['samples'] += 1
            if info['samples'] < self.grace_samples:
                continue

            # Process is gone. Is its memory still accounted for?
            claimed = sum(current.values())
            unclaimed = (mem_total_used - claimed) if mem_total_used is not None else None

            if unclaimed is not None and unclaimed > self.threshold_mb:
                alert = {
                    'type': 'VRAM_RESIDUAL',
                    'severity': 'CRITICAL',
                    'gpu': row.get('index'),
                    'exited_pid': pid,
                    'mem_held_at_exit_mb': round(info['mem_at_exit'], 1),
                    'unclaimed_mb': round(unclaimed, 1),
                    'memory_used_total_mb': mem_total_used,
                    'memory_claimed_by_live_procs_mb': round(claimed, 1),
                    'nvml_util_memory': row.get('utilization.memory'),
                    'timestamp': row.get('iso_timestamp'),
                    'message': (f"PID {pid} exited; {unclaimed:.0f}MB remains allocated "
                                f"with no owning process"),
                }
            del self.pending[pid]

        self.known_pids = current
        return alert


# --------------------------------------------------------------------------
# 3. Power side channel  (periodicity, corrected)
# --------------------------------------------------------------------------

class PowerPeriodicityDetector:
    """Periodic structure in power draw.

    Replaces the previous TimingCovertChannelDetector, whose 'regularity'
    score counted direction REVERSALS -- which is high for random jitter and
    LOW for an actual square wave. It fired on noise and was blind to signal.

    This uses normalised autocorrelation. A real periodic channel produces a
    strong peak at its period lag; white noise does not.
    """

    def __init__(self, window=200, min_amplitude_w=5.0, corr_threshold=0.6,
                 min_lag=3):
        self.window = window
        self.min_amplitude = min_amplitude_w
        self.corr_threshold = corr_threshold
        self.min_lag = min_lag
        self.history = collections.deque(maxlen=window)
        self.state = _EventState(require_consecutive=2, refire_after_s=300)

    @staticmethod
    def _autocorr_peak(vals, min_lag):
        n = len(vals)
        mean = sum(vals) / n
        dev = [v - mean for v in vals]
        var = sum(d * d for d in dev)
        if var <= 0:
            return 0.0, 0
        best_r, best_lag = 0.0, 0
        for lag in range(min_lag, n // 2):
            s = sum(dev[i] * dev[i + lag] for i in range(n - lag))
            r = s / var
            if r > best_r:
                best_r, best_lag = r, lag
        return best_r, best_lag

    def update(self, row):
        power = _f(row, 'power.draw')
        if power is None:
            return None
        self.history.append(power)
        if len(self.history) < self.window:
            return None

        vals = list(self.history)
        amplitude = max(vals) - min(vals)
        if amplitude < self.min_amplitude:
            self.state.should_emit(False)
            return None

        r, lag = self._autocorr_peak(vals, self.min_lag)
        condition = r >= self.corr_threshold

        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'POWER_PERIODICITY',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'autocorr': round(r, 3),
            'period_samples': lag,
            'amplitude_w': round(amplitude, 2),
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Periodic power structure: autocorr {r:.2f} at lag {lag} "
                        f"samples, amplitude {amplitude:.1f}W. Cause unconfirmed."),
        }


# --------------------------------------------------------------------------
# 4. Multi-GPU correlation  (INFO context, not accusation)
# --------------------------------------------------------------------------

class MultiGPUCorrelation:
    """Annotates when anomalies co-occur across GPUs.

    NOT an attack signal. Coordinated simultaneous bursts across GPUs are
    documented architectural behaviour on A100 SXM and B200. Severity is INFO
    and the message says so.
    """

    def __init__(self, correlation_window=300, min_gpus=2):
        self.correlation_window = correlation_window
        self.min_gpus = min_gpus
        self.gpu_events = {}
        self.state = _EventState(require_consecutive=1, refire_after_s=600)

    def add_alert(self, alert):
        gpu = str(alert.get('gpu', 'unknown'))
        self.gpu_events.setdefault(gpu, []).append(
            {'type': alert['type'], 'time': time.time()}
        )
        now = time.time()
        for g in list(self.gpu_events):
            self.gpu_events[g] = [
                e for e in self.gpu_events[g]
                if now - e['time'] < self.correlation_window
            ]
        active = [g for g in self.gpu_events if self.gpu_events[g]]

        if not self.state.should_emit(len(active) >= self.min_gpus):
            return None

        return {
            'type': 'MULTI_GPU_CORRELATION',
            'severity': 'INFO',
            'affected_gpus': active,
            'timestamp': datetime.now().isoformat(),
            'message': (f"Anomalies co-occurring on {len(active)} GPUs. Note: "
                        f"coordinated bursts are known architectural behaviour "
                        f"on A100 SXM / B200. Context only."),
        }


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------

class DetectionPipeline:
    def __init__(self, on_alert=None, vram_strict=True):
        self.on_alert = on_alert
        self.ghost_power = GhostPowerDetector()
        self.vram_residual = VRAMResidualDetector(strict=vram_strict)
        self.periodicity = PowerPeriodicityDetector()
        self.correlation = MultiGPUCorrelation()
        self.alert_count = 0
        self.sample_count = 0

    @property
    def engines(self):
        return [self.ghost_power, self.vram_residual, self.periodicity]

    def process(self, row):
        self.sample_count += 1
        emitted = []
        for engine in self.engines:
            alert = engine.update(row)
            if not alert:
                continue
            self.alert_count += 1
            self._emit(alert)
            emitted.append(alert)
            ctx = self.correlation.add_alert(alert)
            if ctx:
                self._emit(ctx)
                emitted.append(ctx)
        return emitted

    def stats(self):
        rate = self.alert_count / self.sample_count if self.sample_count else 0.0
        return {
            'samples': self.sample_count,
            'alerts': self.alert_count,
            'alerts_per_sample': round(rate, 6),
            'ghost_power_baseline_w': self.ghost_power.baseline_w,
        }

    def _emit(self, alert):
        print(f"[{alert['severity']}] {alert['type']} — {alert['message']}")
        if self.on_alert:
            self.on_alert(alert)
