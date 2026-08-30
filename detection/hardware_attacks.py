# Author: Manmohan (Mike) Bains -- Watchdog
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
        # FIX: _f() has default=0.0 so a missing key returns 0.0 not None.
        # A missing clocks.sm returning 0.0 looks like the GPU is throttled
        # to zero -- could fire falsely on any GPU that omits this field.
        sm_clock = _f(row, 'clocks.sm') if 'clocks.sm' in row else None
        util = _f(row, 'utilization.gpu') if 'utilization.gpu' in row else None
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
        # FIX: _f() has default=0.0 so a missing key returns 0.0 not None.
        # A missing power.draw returning 0.0 would silently contaminate
        # the ghost-power baseline with 'GPU drawing 0W' samples.
        power = _f(row, 'power.draw') if 'power.draw' in row else None
        util = _f(row, 'utilization.gpu') if 'utilization.gpu' in row else None
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


class NVLinkContentionDetector:
    """
    Detects NVLink traffic elevated above this GPU's own learned normal
    floor while compute utilization stays low -- consistent with the
    covert/side-channel threat model demonstrated in "Spy in the
    GPU-box" (Dutta et al., ISCA 2023), NVBleed (Zhang et al., arXiv
    2503.17847, 2025 -- includes a demonstrated cross-VM attack on GCP,
    not just a lab bench), and SideLink (2026). All three show NVLink
    contention can be exploited as a cross-tenant covert channel or
    side channel between GPUs sharing an interconnect.

    HONEST LIMITATION, stated up front rather than hidden: this exact
    pattern -- NVLink traffic while compute utilization is temporarily
    low -- is ALSO exactly what legitimate distributed training
    produces during collective communication (all-reduce, all-gather,
    pipeline-parallel hand-offs), where GPUs synchronize gradients or
    activations in bursts between compute phases. This detector cannot
    distinguish a covert channel from a normal training synchronization
    phase using nvidia-smi-level telemetry alone. Treat this the same
    as DMAAttackDetector and SequentialVRAMReadDetector above: a real
    signal with a real, disclosed discrimination gap, not a
    confirmed-attack detector.

    SCOPE LIMITATION: operates on this GPU's own NVLink counters only,
    same as every other detector in this file. It does not attempt
    pairwise or topology-aware analysis (which GPU is talking to which
    other GPU) -- even though the cited attacks specifically exploit
    contention between a particular busy pair and a particular victim
    pair. This is a first-pass, single-GPU approximation, not a full
    defense against the attacks cited above.

    INTEGRATION STATUS: requires row['nvlink_available'],
    row['nvlink_tx_kbs'], row['nvlink_rx_kbs'] merged into the standard
    telemetry row -- see agent/telemetry.py's sample_nvlink(). That
    function deliberately is NOT auto-called from the main per-sample
    hot path (a subprocess call per GPU per sample at high Hz would
    silently degrade the achieved rate DeltaTimedSampler exists to
    honestly measure). Wiring sample_nvlink() into the live collection
    loop at an appropriate, separately-rate-limited cadence is a
    deliberate follow-up integration step, not yet done -- same
    "built, tested, not yet wired into the live pipeline" status
    ThroughputContentionDetector had before tonight's API work.

    UNVALIDATED default: delta_threshold_kbs has never been tuned
    against real NVLink traffic on real hardware. Treat it as a
    starting point for real-hardware calibration, not a validated
    value.
    """
    def __init__(self, delta_threshold_kbs=1000.0, baseline_min_samples=30,
                 baseline_window=300, util_ceiling=15.0,
                 require_consecutive=5, refire_after_s=120):
        self.delta_threshold_kbs = delta_threshold_kbs
        self.baseline_min_samples = baseline_min_samples
        self.util_ceiling = util_ceiling
        self.idle_samples = collections.deque(maxlen=baseline_window)
        self.baseline_kbs = None
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)
        # NEW: per-link baseline tracking, additive alongside the
        # existing combined baseline above -- does not replace it.
        self.idle_samples_by_link = collections.defaultdict(lambda: collections.deque(maxlen=baseline_window))
        self.baseline_by_link = {}
        # FIX: nvidia-smi's NVLink counters are cumulative since boot,
        # not a rate. Everything below compared cumulative values
        # directly, which is why a real 90s test produced 61.5 billion
        # "KB/s" -- that was counter drift over an unmeasured span of
        # time, not throughput. These three fields hold the previous
        # sample so update() can convert to a genuine per-second rate
        # before any baseline or threshold logic runs.
        self._last_iso_ts = None
        self._last_total_kbs = None
        self._last_by_link = {}
        self._last_raw_total_kbs = None

    def update(self, row):
        if not row.get('nvlink_available'):
            return None
        util = _f(row, 'utilization.gpu')
        tx = row.get('nvlink_tx_kbs')
        rx = row.get('nvlink_rx_kbs')
        if util is None or tx is None or rx is None:
            return None
        raw_total_kbs = tx + rx

        # NEW: per-link combined (tx+rx) totals, additive -- built the
        # same way as the existing combined total above.
        tx_by_link = row.get('nvlink_tx_kbs_by_link') or {}
        rx_by_link = row.get('nvlink_rx_kbs_by_link') or {}
        raw_combined_by_link = {}
        for link in set(tx_by_link) | set(rx_by_link):
            raw_combined_by_link[link] = tx_by_link.get(link, 0.0) + rx_by_link.get(link, 0.0)

        # FIX: convert cumulative counters to a real per-second rate
        # before any baseline/threshold logic runs. Comparing raw
        # cumulative values (as this class did before this fix)
        # measures elapsed time, not traffic, and will eventually cross
        # any fixed threshold on a fully idle GPU given enough runtime.
        iso_ts = row.get('iso_timestamp')
        if not iso_ts:
            # Can't compute a rate without a real timestamp on this row.
            # Fail closed rather than guess, same discipline as the rest
            # of this class.
            return None
        try:
            now_dt = datetime.fromisoformat(iso_ts)
        except (TypeError, ValueError):
            return None

        if self._last_iso_ts is None:
            self._last_iso_ts = now_dt
            self._last_total_kbs = raw_total_kbs
            self._last_raw_total_kbs = raw_total_kbs
            self._last_by_link = dict(raw_combined_by_link)
            return None

        # FIX: the NVLink sampler's cache only refreshes once per
        # nvlink_interval_s (5s default), but update() is called at the
        # full telemetry sample rate (~6-7Hz observed). Between real
        # refreshes, raw_total_kbs is a REPEATED cached value -- computing
        # a rate against it produces delta=0, then the single sample where
        # the cache DOES refresh shows the full 5s of growth compressed
        # into one ~150ms interval, an artificial ~30x spike. That spike
        # can satisfy delta_threshold_kbs but can never satisfy
        # require_consecutive since every other sample resets to 0.
        # Skip evaluation entirely on repeated cache values -- only
        # compute a rate when the raw counter has genuinely changed.
        if raw_total_kbs == self._last_raw_total_kbs:
            return None
        self._last_raw_total_kbs = raw_total_kbs

        elapsed = (now_dt - self._last_iso_ts).total_seconds()
        if elapsed <= 0:
            return None

        total_kbs = max(0.0, raw_total_kbs - self._last_total_kbs) / elapsed
        combined_by_link = {}
        for link, val in raw_combined_by_link.items():
            prev = self._last_by_link.get(link, val)
            combined_by_link[link] = max(0.0, val - prev) / elapsed

        self._last_iso_ts = now_dt
        self._last_total_kbs = raw_total_kbs
        self._last_by_link = dict(raw_combined_by_link)

        if self.baseline_kbs is None:
            if util < self.util_ceiling:
                self.idle_samples.append(total_kbs)
                for link, val in combined_by_link.items():
                    self.idle_samples_by_link[link].append(val)
            if len(self.idle_samples) >= self.baseline_min_samples:
                vals = sorted(self.idle_samples)
                self.baseline_kbs = vals[len(vals) // 2]
                for link, samples in self.idle_samples_by_link.items():
                    if len(samples) >= self.baseline_min_samples:
                        lvals = sorted(samples)
                        self.baseline_by_link[link] = lvals[len(lvals) // 2]

        if self.baseline_kbs is None:
            return None

        delta = total_kbs - self.baseline_kbs
        condition = util < self.util_ceiling and delta > self.delta_threshold_kbs
        if not self.state.should_emit(condition):
            return None

        # NEW: best-effort attribution of which single link deviates most
        # from ITS OWN baseline -- explicitly best-effort, not confirmed
        # pairwise/topology-aware analysis (this class already discloses
        # it does not do that). None when insufficient per-link baseline
        # data exists yet.
        link_index = None
        max_link_delta = None
        for link, val in combined_by_link.items():
            link_baseline = self.baseline_by_link.get(link)
            if link_baseline is None:
                continue
            link_delta = val - link_baseline
            if max_link_delta is None or link_delta > max_link_delta:
                max_link_delta = link_delta
                link_index = link

        return {
            'type': 'NVLINK_CONTENTION',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'nvlink_total_kbs': round(total_kbs, 1),
            'baseline_kbs': round(self.baseline_kbs, 1),
            'delta_kbs': round(delta, 1),
            'utilization': util,
            'link_index': link_index,
            'link_index_note': (
                'Best-effort: the single link whose own traffic deviates '
                'most from its own learned baseline. Not confirmed '
                'pairwise/topology-aware attribution. None when per-link '
                'baseline data is not yet established.'
            ),
            'timestamp': row.get('iso_timestamp'),
            'message': (f"NVLink traffic {delta:.0f}KB/s above this GPU's "
                        f"own learned baseline at {util:.0f}% compute -- "
                        f"cause unconfirmed, consistent with a covert-"
                        f"channel attempt (see Spy-in-the-GPU-box/NVBleed/"
                        f"SideLink) OR normal distributed-training "
                        f"collective communication (all-reduce/all-gather), "
                        f"which produces an identical signature and cannot "
                        f"be ruled out from this telemetry alone"),
        }


class ECCUnavailable(RuntimeError):
    """Raised when strict=True and the row carries no ECC fields.

    Local rather than shared, matching VRAMResidualDetector: a detector
    that silently reports clean on absent input is worse than one that
    refuses to run.
    """
    pass


class ECCAnomalyDetector:
    """Detects abnormal ECC error rates -- the observable signature of
    Rowhammer-style bit-flip induction on GPU memory.

    Published research (GPUHammer, 2025) shows repeated row activation
    can induce bit flips in GDDR-based GPU memory, degrading AI model
    accuracy. The attack is invisible to standard tooling; what IS
    visible is the ECC subsystem correcting an abnormal volume.

    HONEST LIMITS, stated in the alert rather than hidden:
      - Correctable ECC errors also arise from cosmic rays, aging
        silicon, thermal stress, and marginal memory. Elevated rate is
        NOT proof of attack.
      - HBM parts (A100/H100/H200/B200) have stronger ECC than the GDDR
        parts GPUHammer targeted. A negative here does not clear the
        hardware.
      - Detects the CONSEQUENCE, not the attack. Cannot attribute.

    COUNTER SEMANTICS: nvidia-smi reports ECC as CUMULATIVE totals --
    the same trap that produced a 61.5-billion 'KB/s' reading in
    NVLinkContentionDetector before it was fixed. Computes a real
    per-second rate from consecutive iso_timestamps and skips
    evaluation entirely when the raw counter has not moved.
    """

    CORRECTED_FIELD = 'ecc.errors.corrected.volatile.total'
    UNCORRECTED_FIELD = 'ecc.errors.uncorrected.volatile.total'

    def __init__(self, corrected_rate_threshold=1.0,
                 baseline_window=30, baseline_min_samples=10,
                 require_consecutive=3, refire_after_s=300, strict=True):
        self.corrected_rate_threshold = corrected_rate_threshold
        self.baseline_window = baseline_window
        self.baseline_min_samples = baseline_min_samples
        self.strict = strict
        self.idle_samples = collections.deque(maxlen=baseline_window)
        self.baseline_rate = None
        self._last_iso_ts = None
        self._last_corrected = None
        self._last_raw_corrected = None
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        # NOTE: _shared._f has default=0.0, so a missing key returns 0.0
        # rather than None. Presence must be checked on the row itself.
        has_corrected = self.CORRECTED_FIELD in row
        has_uncorrected = self.UNCORRECTED_FIELD in row
        corrected = _f(row, self.CORRECTED_FIELD) if has_corrected else None
        uncorrected = _f(row, self.UNCORRECTED_FIELD) if has_uncorrected else None

        if not has_corrected and not has_uncorrected:
            if self.strict:
                raise ECCUnavailable(
                    "row has no ECC fields; refusing to report clean "
                    "on absent data")
            return None

        if uncorrected is not None and uncorrected > 0:
            return {
                'type': 'ECC_UNCORRECTABLE',
                'severity': 'CRITICAL',
                'gpu': row.get('index'),
                'uncorrected_total': uncorrected,
                'timestamp': row.get('iso_timestamp'),
                'message': (f"{uncorrected:.0f} uncorrectable ECC error(s) -- "
                            f"data integrity not guaranteed on this device. "
                            f"Cause unconfirmed: consistent with failing "
                            f"memory, severe thermal stress, or deliberate "
                            f"bit-flip induction (see GPUHammer). Detects the "
                            f"consequence, not the cause."),
            }

        if corrected is None:
            return None

        iso_ts = row.get('iso_timestamp')
        if not iso_ts:
            return None
        try:
            now_dt = datetime.fromisoformat(iso_ts)
        except (TypeError, ValueError):
            return None

        if self._last_iso_ts is None:
            self._last_iso_ts = now_dt
            self._last_corrected = corrected
            self._last_raw_corrected = corrected
            return None

        if corrected == self._last_raw_corrected:
            return None
        self._last_raw_corrected = corrected

        elapsed = (now_dt - self._last_iso_ts).total_seconds()
        if elapsed <= 0:
            return None

        rate = max(0.0, corrected - self._last_corrected) / elapsed
        self._last_iso_ts = now_dt
        self._last_corrected = corrected

        if self.baseline_rate is None:
            self.idle_samples.append(rate)
            if len(self.idle_samples) < self.baseline_min_samples:
                return None
            vals = sorted(self.idle_samples)
            self.baseline_rate = vals[len(vals) // 2]
            return None

        delta = rate - self.baseline_rate
        if not self.state.should_emit(delta > self.corrected_rate_threshold):
            return None

        return {
            'type': 'ECC_CORRECTED_RATE_ANOMALY',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'corrected_rate_per_s': round(rate, 3),
            'baseline_rate_per_s': round(self.baseline_rate, 3),
            'delta_per_s': round(delta, 3),
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Correctable ECC error rate {delta:.2f}/s above this "
                        f"GPU's own learned baseline -- cause unconfirmed. "
                        f"Consistent with Rowhammer-style bit-flip induction "
                        f"(see GPUHammer) OR with cosmic-ray upset, aging "
                        f"silicon, thermal stress, or a marginal memory part, "
                        f"which produce an identical signature and cannot be "
                        f"ruled out from this telemetry alone."),
        }


class ThermalSideChannelDetector:
    """Detects thermal-utilization decoupling: the die running hotter
    than this GPU's own compute load accounts for.

    Published research (Hot Pixels, USENIX Security 2023) shows
    frequency, power and temperature are exploitable side channels on
    GPUs. The defensive read is narrower and is all this claims: when
    temperature is elevated while THIS GPU reports little compute, heat
    is arriving from somewhere the local workload does not explain.

    HONEST LIMITS:
      - A neighbouring GPU, a cooling change, or an ambient shift
        produces an identical signature.
      - On shared hardware, co-tenant activity is the ordinary
        explanation, not the alarming one.
      - Recovers NO co-tenant data. Observes decoupling only.

    Deliberately INFO severity. An INFO observation that a shared
    thermal domain is active is honest; calling it an attack is not.
    """

    def __init__(self, util_ceiling=15.0, temp_delta_threshold=8.0,
                 baseline_window=60, baseline_min_samples=20,
                 require_consecutive=5, refire_after_s=600):
        self.util_ceiling = util_ceiling
        self.temp_delta_threshold = temp_delta_threshold
        self.baseline_window = baseline_window
        self.baseline_min_samples = baseline_min_samples
        self.idle_temps = collections.deque(maxlen=baseline_window)
        self.baseline_temp = None
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        temp = _f(row, 'temperature.gpu')
        util = _f(row, 'utilization.gpu')
        if temp is None or util is None:
            return None

        if util > self.util_ceiling:
            return None

        if self.baseline_temp is None:
            self.idle_temps.append(temp)
            if len(self.idle_temps) < self.baseline_min_samples:
                return None
            vals = sorted(self.idle_temps)
            self.baseline_temp = vals[len(vals) // 2]
            return None

        delta = temp - self.baseline_temp
        if not self.state.should_emit(delta > self.temp_delta_threshold):
            return None

        return {
            'type': 'THERMAL_UTILIZATION_DECOUPLING',
            'severity': 'INFO',
            'gpu': row.get('index'),
            'temperature_c': round(temp, 1),
            'baseline_temp_c': round(self.baseline_temp, 1),
            'delta_c': round(delta, 1),
            'utilization': util,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Die temperature {delta:.1f}C above this GPU's own "
                        f"learned idle baseline at {util:.0f}% local compute "
                        f"-- heat not accounted for by local workload. Cause "
                        f"unconfirmed: consistent with co-tenant activity in a "
                        f"shared thermal domain, a neighbouring device, or an "
                        f"ambient/cooling change. Context only -- no data is "
                        f"recovered or inferred from this signal."),
        }


class PCIeTelemetryUnavailable(RuntimeError):
    """Raised when strict=True and no PCIe throughput fields exist."""
    pass


class PCIeAnomalyDetector:
    """Detects sustained PCIe traffic while this GPU reports little
    compute -- bulk data movement without local computation.

    Published research (Invisible Probe, IEEE S&P 2021; LockedDown,
    EuroS&P 2022) establishes host-GPU PCIe contention as a practical
    side channel, and PCIe traffic is readable in the clear without bus
    encryption.

    HONEST LIMITS:
      - Model loading, checkpoint writes, dataset streaming and
        host-pinned transfers all produce this exact signature during
        entirely legitimate use.
      - Cannot distinguish exfiltration from an ordinary large read.
      - PCIe fields are not present in every telemetry configuration;
        strict=True raises rather than reporting clean.
    """

    RX_FIELDS = ('pcie_rx_mbs', 'pcie.rx.throughput', 'pcie_rx_mb_s')
    TX_FIELDS = ('pcie_tx_mbs', 'pcie.tx.throughput', 'pcie_tx_mb_s')

    def __init__(self, util_ceiling=10.0, throughput_threshold_mbs=100.0,
                 baseline_window=30, baseline_min_samples=10,
                 require_consecutive=4, refire_after_s=300, strict=True):
        self.util_ceiling = util_ceiling
        self.throughput_threshold_mbs = throughput_threshold_mbs
        self.baseline_window = baseline_window
        self.baseline_min_samples = baseline_min_samples
        self.strict = strict
        self.idle_samples = collections.deque(maxlen=baseline_window)
        self.baseline_mbs = None
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def _first_present(self, row, names):
        # _shared._f has default=0.0, so check key presence on the row.
        for n in names:
            if n in row:
                v = _f(row, n)
                if v is not None:
                    return v
        return None

    def update(self, row):
        rx = self._first_present(row, self.RX_FIELDS)
        tx = self._first_present(row, self.TX_FIELDS)
        if rx is None and tx is None:
            if self.strict:
                raise PCIeTelemetryUnavailable(
                    "row carries no PCIe throughput fields; refusing to "
                    "report clean on absent data")
            return None

        total_mbs = (rx or 0.0) + (tx or 0.0)
        util = _f(row, 'utilization.gpu')
        if util is None:
            return None

        if util > self.util_ceiling:
            return None

        if self.baseline_mbs is None:
            self.idle_samples.append(total_mbs)
            if len(self.idle_samples) < self.baseline_min_samples:
                return None
            vals = sorted(self.idle_samples)
            self.baseline_mbs = vals[len(vals) // 2]
            return None

        delta = total_mbs - self.baseline_mbs
        if not self.state.should_emit(delta > self.throughput_threshold_mbs):
            return None

        return {
            'type': 'PCIE_TRANSFER_AT_LOW_COMPUTE',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'pcie_total_mbs': round(total_mbs, 1),
            'pcie_rx_mbs': round(rx, 1) if rx is not None else None,
            'pcie_tx_mbs': round(tx, 1) if tx is not None else None,
            'baseline_mbs': round(self.baseline_mbs, 1),
            'delta_mbs': round(delta, 1),
            'utilization': util,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"PCIe throughput {delta:.0f}MB/s above this GPU's own "
                        f"learned baseline at {util:.0f}% compute -- bulk "
                        f"transfer without local computation. Cause "
                        f"unconfirmed: consistent with a PCIe-bus side channel "
                        f"(see Invisible Probe/LockedDown) OR with ordinary "
                        f"model loading, checkpointing, or dataset streaming, "
                        f"which produce an identical signature and cannot be "
                        f"ruled out from this telemetry alone."),
        }
