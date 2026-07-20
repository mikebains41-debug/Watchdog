import time, collections, subprocess
from datetime import datetime
from detection._shared import _EventState, _f


class CacheSideChannelDetector:
    """
    Detects a high proportion of memory-bandwidth activity samples while
    average GPU compute utilization stays low.

    FIXED vs. original:
      - Was level-triggered via last_alert cooldown -- fired on the first
        qualifying 200-sample window, then just rate-limited. Now
        edge-triggered via _EventState.
      - float(row.get(...)) N/A-safe.
      - "possible L2 cache side-channel" stated a specific mechanism as
        established fact. This detector's signal (elevated memory
        bandwidth at low compute) substantially overlaps with
        DMAAttackDetector and SequentialVRAMReadDetector in this same
        repo -- three detectors watching a similar underlying pattern
        with different framings. Whether these should be consolidated is
        a separate decision, not made unilaterally here. Severity
        downgraded CRITICAL -> WARNING and message reworded to state the
        cause is unconfirmed rather than naming a specific mechanism.
    """
    def __init__(self, spike_ratio_threshold=0.4, util_mem_spike_threshold=50.0,
                 avg_gpu_ceiling=15.0, window=200,
                 require_consecutive=3, refire_after_s=60):
        self.spike_ratio_threshold = spike_ratio_threshold
        self.util_mem_spike_threshold = util_mem_spike_threshold
        self.avg_gpu_ceiling = avg_gpu_ceiling
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        util_gpu = _f(row, 'utilization.gpu')
        util_mem = _f(row, 'utilization.memory')
        if util_gpu is None or util_mem is None:
            return None
        self.history.append({'util_gpu': util_gpu, 'util_mem': util_mem})
        if len(self.history) < self.window:
            return None
        vals = list(self.history)
        mem_spikes = sum(1 for v in vals if v['util_mem'] > self.util_mem_spike_threshold)
        avg_gpu = sum(v['util_gpu'] for v in vals) / len(vals)
        spike_ratio = mem_spikes / self.window

        condition = (spike_ratio > self.spike_ratio_threshold
                     and avg_gpu < self.avg_gpu_ceiling)
        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'CACHE_SIDE_CHANNEL',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'mem_util_spike_ratio': round(spike_ratio, 3),
            'avg_gpu_util': round(avg_gpu, 2),
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Memory-bandwidth spikes in {spike_ratio*100:.0f}% "
                        f"of the last {self.window} samples at avg "
                        f"{avg_gpu:.1f}% compute -- cause unconfirmed, "
                        f"overlaps with DMAAttackDetector and "
                        f"SequentialVRAMReadDetector's signal"),
        }


class MIGPartitionDesyncDetector:
    """
    Detects elevated memory-bandwidth activity while GPU compute
    utilization reports 0%, checked against MIG partition state context.

    FIXED vs. original:
      - Fixed util_mem>40 threshold with no baseline at all. Replaced
        with a learned per-GPU median idle-mem-bandwidth floor, same
        pattern as GhostPowerDetector/DMAAttackDetector.
      - Was level-triggered via a 60s cooldown with NO debounce at all --
        fired on the very first qualifying sample. Now edge-triggered.
      - float(row.get(...)) N/A-safe.
      - The 'nvidia-smi mig -lgip' context call ran regardless of whether
        MIG is actually configured on this GPU -- most rented GPUs do
        not have MIG enabled at all, in which case this detector's
        specific "cross-partition" framing doesn't apply. Now checks
        whether the mig_info output actually indicates configured
        instances before making that specific claim.
      - This detector's underlying signal (mem bandwidth elevated at 0%
        compute) substantially overlaps with GhostPowerDetector and
        DMAAttackDetector. Noted honestly, not resolved by merging here.
        Severity downgraded CRITICAL -> WARNING.
    """
    def __init__(self, util_mem_delta_threshold=20.0, baseline_min_samples=30,
                 baseline_window=300, require_consecutive=3,
                 refire_after_s=60):
        self.util_mem_delta_threshold = util_mem_delta_threshold
        self.baseline_min_samples = baseline_min_samples
        self.idle_samples = collections.deque(maxlen=baseline_window)
        self.baseline_util_mem = None
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        util_gpu = _f(row, 'utilization.gpu')
        util_mem = _f(row, 'utilization.memory')
        if util_gpu is None or util_mem is None:
            return None

        if self.baseline_util_mem is None:
            if util_gpu == 0:
                self.idle_samples.append(util_mem)
            if len(self.idle_samples) >= self.baseline_min_samples:
                vals = sorted(self.idle_samples)
                self.baseline_util_mem = vals[len(vals) // 2]

        if self.baseline_util_mem is None:
            return None

        delta = util_mem - self.baseline_util_mem
        condition = util_gpu == 0 and delta > self.util_mem_delta_threshold
        if not self.state.should_emit(condition):
            return None

        try:
            r = subprocess.run(['nvidia-smi', 'mig', '-lgip'],
                                capture_output=True, text=True, timeout=5)
            mig_info = r.stdout.strip()[:200]
        except Exception:
            mig_info = 'UNAVAILABLE'
        # UNVERIFIED against real hardware -- no GPU exists in the
        # environment that wrote this to confirm nvidia-smi's exact
        # wording when MIG isn't configured. Broadened to several
        # plausible negative-indicator phrasings rather than one exact
        # string, and defaults to "not configured" (the safer direction
        # to be wrong in) for anything that doesn't look like populated
        # instance data.
        NEGATIVE_INDICATORS = ('No MIG', 'No devices found', 'not supported',
                                'Not Supported', 'No GPU instances found')
        mig_configured = (bool(mig_info) and mig_info not in ('UNAVAILABLE', '')
                           and not any(neg in mig_info for neg in NEGATIVE_INDICATORS))

        return {
            'type': 'MIG_PARTITION_DESYNC',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'util_mem': util_mem,
            'baseline_util_mem': round(self.baseline_util_mem, 2),
            'delta': round(delta, 2),
            'mig_configured': mig_configured,
            'mig_info': mig_info,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Memory bandwidth {delta:.1f}% above this GPU's "
                        f"own learned idle floor at 0% compute -- cause "
                        f"unconfirmed, overlaps with GhostPowerDetector "
                        f"and DMAAttackDetector"
                        + ("" if mig_configured else
                           " (no MIG partitions appear configured on "
                           "this GPU, so the cross-partition framing "
                           "may not apply here)")),
        }


class SequentialVRAMReadDetector:
    """
    Detects high memory-bandwidth utilization covering a large fraction of
    VRAM while GPU compute utilization stays low -- consistent with bulk
    VRAM scraping (e.g. reading another tenant's residual model weights),
    but also indistinguishable from legitimate large-checkpoint loading.

    FIXED vs. original:
      - The original computed a `baseline_mem` from an active-use
        calibration phase but never referenced it anywhere in the firing
        condition -- dead code that looked like it was doing something.
        Removed entirely rather than left as decoration.
      - Was level-triggered via last_alert cooldown. Now edge-triggered
        via _EventState (require_consecutive=5).
      - float(row.get(...)) would crash on '[N/A]'. Now N/A-safe.
      - Default coverage threshold raised from 10% to 30% -- 10% of total
        VRAM is a small fraction to label "bulk" scraping. This default
        is still unvalidated against real hardware and should be tuned
        once real measurement data exists.

    STILL UNRESOLVED, stated rather than hidden: same discrimination gap
    as DMAAttackDetector -- cannot tell this apart from a legitimate large
    checkpoint or dataset load from telemetry alone.
    """

    def __init__(self, coverage_threshold_pct=30.0, util_mem_threshold=60.0,
                 util_gpu_ceiling=5.0, require_consecutive=5,
                 refire_after_s=60):
        self.coverage_threshold_pct = coverage_threshold_pct
        self.util_mem_threshold = util_mem_threshold
        self.util_gpu_ceiling = util_gpu_ceiling
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        mem_used = _f(row, 'memory.used')
        mem_total = _f(row, 'memory.total', default=1.0)
        util_gpu = _f(row, 'utilization.gpu')
        util_mem = _f(row, 'utilization.memory')
        if None in (mem_used, mem_total, util_gpu, util_mem) or mem_total <= 0:
            return None

        coverage_pct = (mem_used / mem_total) * 100

        condition = (util_mem > self.util_mem_threshold
                     and util_gpu < self.util_gpu_ceiling
                     and coverage_pct >= self.coverage_threshold_pct)
        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'SEQUENTIAL_VRAM_READ',
            'severity': 'EMERGENCY',
            'gpu': row.get('index'),
            'memory_used_mb': mem_used,
            'coverage_pct': round(coverage_pct, 2),
            'mem_util_pct': util_mem,
            'gpu_util_pct': util_gpu,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Bulk VRAM read pattern: {coverage_pct:.1f}% of VRAM "
                        f"at {util_mem:.0f}% mem bandwidth, {util_gpu:.0f}% "
                        f"compute -- possible exfiltration OR bulk data load "
                        f"(cannot be distinguished from telemetry alone)"),
        }
