# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog detection engines.

Design rules enforced here:
  1. Edge-triggered, not level-triggered. An alert fires when a condition
     STARTS, not on every sample while it persists.
  2. No detector fires on a state documented as architecturally normal
     (cooldown tails, coordinated multi-GPU bursts, idle floor).
  3. A detector that cannot see its subject in the input does not ship.

Deleted vs. previous version, deliberately:
  - CrossTenantBleedingDetector: duplicate of GhostPowerDetector.
  - ThermalEmanationDetector: fired on every cooldown, which is normal.
  - CrossWorkloadClustering: demoted EMERGENCY -> INFO.

Wired in this version:
  - ThroughputContentionDetector, via a SEPARATE entry point
    (calibrate_throughput / process_throughput), not through process(row).
    It measures a workload's own iterations/sec, which nvidia-smi cannot
    report -- a caller (e.g. the training loop itself) must explicitly
    supply it. Silently trying to derive it from a telemetry row would be
    dishonest about what the detector actually needs.
"""

import time
from datetime import datetime

from detection._shared import _EventState, _f
from detection.throughput_contention_detector import ThroughputContentionDetector


class GhostPowerDetector:
    """Power above the idle floor while NVML reports 0% util.

    Baseline is the MEDIAN of idle samples, not the mean: a ghost event
    contaminating the window would otherwise raise the floor and mask itself.
    """

    def __init__(self, threshold_w=15.0, baseline_min_samples=30,
                 baseline_window=600, idle_mem_mb=500):
        self.threshold_w = threshold_w
        self.baseline_min_samples = baseline_min_samples
        self.idle_mem_mb = idle_mem_mb
        import collections
        self.idle_samples = collections.deque(maxlen=baseline_window)
        self.baseline_w = None
        self.state = _EventState(require_consecutive=3, refire_after_s=300)

    def _update_baseline(self, power, util, mem):
        # FIXED: freeze the baseline once established. Previously this
        # kept recomputing from a rolling window forever, which meant a
        # SUSTAINED ghost-power event -- the exact thing this detector
        # exists to catch -- could slowly become the new "normal" as its
        # own elevated samples filled the window, shrinking delta toward
        # zero and silencing the detector on the attack it should catch.
        #
        # Tradeoff, stated rather than hidden: a frozen baseline won't
        # track slow legitimate drift (firmware updates, thermal paste
        # aging, ambient temperature shifts) over a long-running process.
        # For a security detector, going blind to a sustained real attack
        # is worse than missing gradual environmental drift, so this
        # trades adaptability for attack-resistance deliberately.
        if self.baseline_w is not None:
            return
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
            return None
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


class VRAMResidualUnavailable(RuntimeError):
    """Raised when per-process data is absent. Deliberately not swallowed."""


class VRAMResidualDetector:
    """Memory still allocated after the owning process is gone.

    Requires row['compute_apps'] as a list of {'pid': int, 'used_memory': mb}:
      nvidia-smi --query-compute-apps=pid,used_memory --format=csv,noheader,nounits
    """

    def __init__(self, residual_threshold_mb=100, grace_samples=2, strict=True):
        self.threshold_mb = residual_threshold_mb
        self.grace_samples = grace_samples
        self.strict = strict
        self.known_pids = {}
        self.pending = {}
        self.state = _EventState(require_consecutive=1, refire_after_s=None)

    def update(self, row):
        apps = row.get('compute_apps')
        if apps is None:
            if self.strict:
                raise VRAMResidualUnavailable(
                    "VRAMResidualDetector requires row['compute_apps']. "
                    "Aggregate memory.used cannot distinguish residual memory "
                    "from a resident model. Add --query-compute-apps to the "
                    "collector, or construct with strict=False."
                )
            return None
        mem_total_used = _f(row, 'memory.used')
        current = {int(a['pid']): float(a['used_memory']) for a in apps}
        for pid, last_mem in list(self.known_pids.items()):
            if pid not in current:
                self.pending.setdefault(pid, {'samples': 0, 'mem_at_exit': last_mem})
        alert = None
        for pid, info in list(self.pending.items()):
            info['samples'] += 1
            if info['samples'] < self.grace_samples:
                continue
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
                    'message': (f"PID {pid} exited; {unclaimed:.0f}MB remains "
                                f"allocated with no owning process"),
                }
            del self.pending[pid]
        self.known_pids = current
        return alert


class PowerPeriodicityDetector:
    """Periodic structure in power draw, via normalised autocorrelation.

    Replaces TimingCovertChannelDetector, whose 'regularity' score counted
    direction REVERSALS -- high for random jitter, LOW for a real square wave.
    It fired on noise and was blind to signal.
    """

    def __init__(self, window=200, min_amplitude_w=5.0, corr_threshold=0.6,
                 min_lag=3):
        self.window = window
        self.min_amplitude = min_amplitude_w
        self.corr_threshold = corr_threshold
        self.min_lag = min_lag
        import collections
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
        if not self.state.should_emit(r >= self.corr_threshold):
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


class MultiGPUCorrelation:
    """Annotates anomalies co-occurring across GPUs. NOT an attack signal:
    coordinated bursts are documented architectural behaviour on A100/B200."""

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


class PerGPU:
    """One independent detector instance per GPU, keyed by uuid (else index).

    Found 2026-09-21: DetectionPipeline fed every GPU's rows to ONE instance
    of each engine. GhostPowerDetector then kept one learned floor and one
    consecutive-hit counter for all GPUs, so a GPU with no floor of its own
    was judged against another GPU's floor, and a genuine ghost on one GPU
    was silenced whenever a clean GPU's rows were interleaved (reproduced in
    scripts/repro_ghost_multi_gpu.py). PowerPeriodicityDetector likewise
    searched one power history built from several GPUs interleaved.

    With a single GPU this behaves exactly as the bare detector did.
    Attribute reads (e.g. baseline_w in stats) go to the first GPU seen;
    attribute writes apply to every instance, present and future.
    """

    def __init__(self, factory):
        object.__setattr__(self, "_factory", factory)
        object.__setattr__(self, "_by_gpu", {})
        object.__setattr__(self, "_overrides", {})
        object.__setattr__(self, "_template", factory())

    def _key(self, row):
        k = row.get("uuid") or row.get("index")
        return "default" if k in (None, "") else str(k)

    def for_row(self, row):
        k = self._key(row)
        inst = self._by_gpu.get(k)
        if inst is None:
            inst = self._factory()
            for name, value in self._overrides.items():
                setattr(inst, name, value)
            self._by_gpu[k] = inst
        return inst

    def update(self, row):
        return self.for_row(row).update(row)

    @property
    def per_gpu(self):
        return dict(self._by_gpu)

    def __getattr__(self, name):
        d = object.__getattribute__(self, "__dict__")
        if "_by_gpu" not in d:
            raise AttributeError(name)
        target = next(iter(d["_by_gpu"].values()), None) or d["_template"]
        return getattr(target, name)

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return
        self._overrides[name] = value
        setattr(self._template, name, value)
        for inst in self._by_gpu.values():
            setattr(inst, name, value)


class DetectionPipeline:
    def __init__(self, on_alert=None, vram_strict=True):
        self.on_alert = on_alert
        self.ghost_power = PerGPU(GhostPowerDetector)
        self.vram_residual = VRAMResidualDetector(strict=vram_strict)
        self.periodicity = PerGPU(PowerPeriodicityDetector)
        self.correlation = MultiGPUCorrelation()
        self.throughput_contention = ThroughputContentionDetector()
        self.alert_count = 0
        self.sample_count = 0
        self.throughput_alert_count = 0
        self.throughput_sample_count = 0

    @property
    def engines(self):
        return [self.ghost_power, self.vram_residual, self.periodicity]

    def process(self, row):
        """GPU telemetry row (power/util/mem) -- from nvidia-smi. Does NOT
        touch throughput_contention; see process_throughput() below."""
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

    def calibrate_throughput(self, throughput_sample):
        """
        ThroughputContentionDetector needs a workload's own iterations/sec,
        which nvidia-smi cannot report -- process(row) never reaches this
        detector. A caller (e.g. the training loop itself) must explicitly
        supply known-uncontended samples here before process_throughput()
        will evaluate anything.
        """
        self.throughput_contention.calibrate(throughput_sample)

    def process_throughput(self, throughput_sample, gpu_index=0, timestamp=None):
        """
        Separate entry point, deliberately not folded into process(row).
        See calibrate_throughput() docstring for why.
        """
        self.throughput_sample_count += 1
        alert = self.throughput_contention.update(
            throughput_sample, gpu_index=gpu_index, timestamp=timestamp
        )
        if not alert:
            return None
        self.throughput_alert_count += 1
        self._emit(alert)
        ctx = self.correlation.add_alert(alert)
        if ctx:
            self._emit(ctx)
        return alert

    def stats(self):
        rate = self.alert_count / self.sample_count if self.sample_count else 0.0
        throughput_rate = (self.throughput_alert_count / self.throughput_sample_count
                            if self.throughput_sample_count else 0.0)
        return {
            'samples': self.sample_count,
            'alerts': self.alert_count,
            'alerts_per_sample': round(rate, 6),
            'ghost_power_baseline_w': self.ghost_power.baseline_w,
            'throughput_samples': self.throughput_sample_count,
            'throughput_alerts': self.throughput_alert_count,
            'throughput_alerts_per_sample': round(throughput_rate, 6),
        }

    def _emit(self, alert):
        print(f"[{alert['severity']}] {alert['type']} — {alert['message']}")
        if self.on_alert:
            self.on_alert(alert)
