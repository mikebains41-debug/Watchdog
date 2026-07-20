import time, collections
from datetime import datetime
from detection._shared import _EventState, _f


class InferencePowerFingerprintDetector:
    """
    Detects inference-time power deviation from a calibrated baseline --
    intended as a signal for model substitution or adversarial input,
    though that causal claim cannot be confirmed from power alone.

    FIXED vs. original:
      - Baseline was mean + standard deviation, calibrated once from the
        first N samples with no protection against a contaminated
        calibration window skewing both center and spread. Now median +
        MAD (median absolute deviation) -- a standard robust-statistics
        pairing: a poisoned sample has to be far more extreme to distort
        the median than the mean, and MAD is correspondingly resistant
        compared to standard deviation.
      - Was level-triggered via last_alert cooldown. Now edge-triggered.
      - float(row.get(...)) N/A-safe.
      - Severity CRITICAL -> WARNING: the underlying claim (deviation
        implies substitution/adversarial input) is a hypothesis, not an
        established fact from power alone -- matches how
        PowerPeriodicityDetector in engines.py already handles this.
    """

    def __init__(self, deviation_threshold=0.25, calibration_samples=200,
                 require_consecutive=3, refire_after_s=60):
        self.deviation_threshold = deviation_threshold
        self.calibration_samples = calibration_samples
        self.calibration = []
        self.baseline_median = None
        self.baseline_mad = None
        self.history = collections.deque(maxlen=100)
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        power = _f(row, 'power.draw')
        util = _f(row, 'utilization.gpu')
        if power is None or util is None or util < 10:
            return None

        if self.baseline_median is None:
            if len(self.calibration) < self.calibration_samples:
                self.calibration.append(power)
                return None
            vals = sorted(self.calibration)
            self.baseline_median = vals[len(vals) // 2]
            deviations = sorted(abs(p - self.baseline_median) for p in self.calibration)
            self.baseline_mad = deviations[len(deviations) // 2]
            return None

        self.history.append(power)
        if len(self.history) < 20:
            return None
        recent_vals = sorted(list(self.history)[-20:])
        recent_median = recent_vals[len(recent_vals) // 2]

        if self.baseline_mad == 0:
            return None
        robust_z = abs(recent_median - self.baseline_median) / (self.baseline_mad * 1.4826)

        if not self.state.should_emit(robust_z > self.deviation_threshold * 10):
            return None

        return {
            'type': 'INFERENCE_POWER_ANOMALY',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'baseline_median_w': round(self.baseline_median, 2),
            'current_median_w': round(recent_median, 2),
            'robust_z': round(robust_z, 3),
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Inference power deviation (robust z={robust_z:.2f}) "
                        f"from calibrated baseline -- cause unconfirmed, "
                        f"consistent with workload change, model swap, or "
                        f"adversarial input"),
        }


class AgentOrchestrationAnomalyDetector:
    """
    Detects power staying elevated while an agent claims to be idle --
    intended as a covert-mining / model-extraction signal.

    FIXED vs. original:
      - Used a FIXED 100W absolute threshold. Independent research (see
        "The Model Parking Tax", arXiv 2605.23918) measured idle-with-
        loaded-context power running 26-66W over bare idle depending on
        GPU architecture -- a fixed 100W threshold can be crossed by
        entirely normal warm-serving idle state, especially on GDDR6
        architectures. Replaced with a LEARNED per-GPU median idle floor,
        matching GhostPowerDetector's approach, so the trigger is
        relative to this device's own observed normal state, not an
        arbitrary constant.
      - Was level-triggered via last_alert cooldown. Now edge-triggered.
      - float(row.get(...)) N/A-safe.
      - Severity CRITICAL -> WARNING, same reasoning as
        InferencePowerFingerprintDetector above.

    OPEN QUESTION, not resolved here: this detector's signal (power
    elevated at low utilization) substantially overlaps with
    GhostPowerDetector in detection/engines.py. Whether these should be
    merged is a decision for a separate pass -- not made unilaterally here.
    """

    def __init__(self, delta_threshold_w=50.0, baseline_min_samples=30,
                 baseline_window=300, util_ceiling=10.0,
                 require_consecutive=5, refire_after_s=60):
        self.delta_threshold_w = delta_threshold_w
        self.baseline_min_samples = baseline_min_samples
        self.util_ceiling = util_ceiling
        self.idle_samples = collections.deque(maxlen=baseline_window)
        self.baseline_w = None
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        power = _f(row, 'power.draw')
        util = _f(row, 'utilization.gpu')
        if power is None or util is None:
            return None

        if self.baseline_w is None:
            if util < self.util_ceiling:
                self.idle_samples.append(power)
            if len(self.idle_samples) >= self.baseline_min_samples:
                vals = sorted(self.idle_samples)
                self.baseline_w = vals[len(vals) // 2]

        if self.baseline_w is None:
            return None

        delta = power - self.baseline_w
        condition = util < self.util_ceiling and delta > self.delta_threshold_w
        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'AGENT_ORCHESTRATION_ANOMALY',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'power_w': round(power, 2),
            'baseline_w': round(self.baseline_w, 2),
            'delta_w': round(delta, 2),
            'utilization': util,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Power {delta:.1f}W above this GPU's own learned "
                        f"idle-with-context floor while claiming idle -- "
                        f"cause unconfirmed, overlaps with GhostPowerDetector"),
        }


class PromptInjectionSideEffectDetector:
    """
    Detects a power spike during active inference, relative to this
    session's own calibrated baseline.

    FIXED vs. original:
      - Compared the window's own max to the window's own mean -- not a
        baseline-vs-deviation comparison. Natural power variance from
        different prompt lengths, batch composition, or KV-cache growth
        during normal inference would trigger this. Replaced with a
        properly separate calibrated baseline (median + MAD), same
        pattern as InferencePowerFingerprintDetector -- which watches a
        substantially overlapping signal (power deviation during active
        inference) under a different framing. Noted, not resolved by
        merging here.
      - Was level-triggered via last_alert cooldown. Now edge-triggered.
      - float(row.get(...)) N/A-safe.
      - "possible adversarial prompt or jailbreak" stated the cause as
        established. Message reworded to state the deviation is
        unconfirmed as to cause. Severity kept at WARNING.
    """
    def __init__(self, deviation_threshold_w=30.0, calibration_samples=50,
                 util_floor=20.0, require_consecutive=3, refire_after_s=30):
        self.deviation_threshold_w = deviation_threshold_w
        self.calibration_samples = calibration_samples
        self.util_floor = util_floor
        self.calibration = []
        self.baseline_median = None
        self.baseline_mad = None
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        power = _f(row, 'power.draw')
        util = _f(row, 'utilization.gpu')
        if power is None or util is None or util <= self.util_floor:
            return None

        if self.baseline_median is None:
            if len(self.calibration) < self.calibration_samples:
                self.calibration.append(power)
                return None
            vals = sorted(self.calibration)
            self.baseline_median = vals[len(vals) // 2]
            deviations = sorted(abs(p - self.baseline_median) for p in self.calibration)
            self.baseline_mad = deviations[len(deviations) // 2]
            return None

        delta = power - self.baseline_median
        if not self.state.should_emit(delta > self.deviation_threshold_w):
            return None

        return {
            'type': 'PROMPT_INJECTION_SIDEEFFECT',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'power_w': round(power, 2),
            'baseline_median_w': round(self.baseline_median, 2),
            'delta_w': round(delta, 2),
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Power {delta:.1f}W above this session's "
                        f"calibrated inference baseline -- cause "
                        f"unconfirmed, overlaps with "
                        f"InferencePowerFingerprintDetector's signal, "
                        f"consistent with a longer prompt, larger batch, "
                        f"or an adversarial input"),
        }


class AgentSessionVRAMUnavailable(RuntimeError):
    """
    Raised by AgentSessionVRAMRetentionDetector when row['compute_apps']
    is absent and strict=True. Deliberately a local exception rather than
    importing VRAMResidualUnavailable from detection/engines.py, to avoid
    adding new cross-module coupling this late in this fix pass -- but it
    exists for exactly the same reason: see VRAMResidualDetector's
    docstring in engines.py for the full explanation.
    """
    pass


class AgentSessionVRAMRetentionDetector:
    """
    Detects VRAM retention after an agentic AI session's process exits.
    Directly applies CVE-2048350 (pending MITRE assignment) to the
    agentic AI threat model.

    FIXED vs. original: identical bug and identical fix as
    VRAMResidualDetector in detection/engines.py -- see that class's
    docstring for the full explanation. This detector used aggregate
    memory.used plus an idle-utilization heuristic, with no per-process
    tracking at all -- it could not distinguish a genuinely orphaned
    session from a model sitting resident and idle with its owning
    process still alive, which is the most common state in production
    inference serving. It would have fired continuously on completely
    normal warm-serving idle periods. Replaced with the same PID-exit-
    tracking approach: requires row['compute_apps'], and only fires when
    a specific PID has actually exited and its memory remains unclaimed.

    Kept as its own class (not merged into VRAMResidualDetector) since it
    carries the agentic-AI-specific CVE-2048350 message framing this pass
    was told to preserve, not consolidate.
    """
    def __init__(self, retention_threshold_mb=100, grace_samples=2, strict=True):
        self.retention_threshold_mb = retention_threshold_mb
        self.grace_samples = grace_samples
        self.strict = strict
        self.known_pids = {}
        self.pending = {}
        self.state = _EventState(require_consecutive=1, refire_after_s=60)

    def update(self, row):
        apps = row.get('compute_apps')
        if apps is None:
            if self.strict:
                raise AgentSessionVRAMUnavailable(
                    "AgentSessionVRAMRetentionDetector requires "
                    "row['compute_apps']. See VRAMResidualDetector's "
                    "docstring in detection/engines.py for why aggregate "
                    "memory.used cannot substitute for this."
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
            if info['samples'] >= self.grace_samples and mem_total_used is not None:
                claimed = sum(current.values())
                unclaimed = mem_total_used - claimed
                if unclaimed > self.retention_threshold_mb and self.state.should_emit(True):
                    alert = {
                        'type': 'AGENT_VRAM_RETENTION',
                        'severity': 'CRITICAL',
                        'gpu': row.get('index'),
                        'exited_pid': pid,
                        'mem_held_at_exit_mb': round(info['mem_at_exit'], 1),
                        'unclaimed_mb': round(unclaimed, 1),
                        'memory_used_total_mb': mem_total_used,
                        'threshold_mb': self.retention_threshold_mb,
                        'timestamp': row.get('iso_timestamp'),
                        'message': (f"Agent session (PID {pid}) exited; "
                                    f"{unclaimed:.0f}MB VRAM remains "
                                    f"allocated with no owning process -- "
                                    f"CVE-2048350 (pending MITRE "
                                    f"assignment) applied to agentic AI, "
                                    f"proprietary session data exposure "
                                    f"risk"),
                    }
                if info['samples'] >= self.grace_samples:
                    del self.pending[pid]

        self.known_pids = current
        return alert


class InterAgentHandoffAnomalyDetector:
    """
    Detects anomalous power on agent-to-agent handoff resume, relative to
    this session's own established handoff baseline.

    FIXED vs. original:
      - State bug: when a would-be alert was skipped due to cooldown, the
        original code returned early WITHOUT resetting handoff_detected,
        leaving the state machine inconsistent until the next
        idle-to-active transition. Now resets consistently on every path
        through the resume branch, whether an alert fires or not.
      - "possible malicious payload from upstream agent" was stated as if
        established from a power spike alone. Reworded to state the
        correlation is unconfirmed, matching how the rest of this pass
        treats causal claims that can't be verified from power data.
      - float(row.get(...)) N/A-safe.
      - Severity CRITICAL -> WARNING, same reasoning as above.

    NOTE ON DESIGN: kept on a direct last_alert cooldown rather than
    _EventState. _EventState assumes a persistent boolean condition
    polled every sample; this detector's alert only evaluates at the
    specific moment 10 post-handoff samples accumulate, which is a
    one-shot event trigger, not a continuous condition -- forcing it
    into _EventState's model would be a worse fit than fixing the actual
    reset bug directly.
    """

    def __init__(self, baseline_samples=50, spike_threshold_w=40, window=20,
                 refire_after_s=60):
        self.baseline_samples = baseline_samples
        self.spike_threshold = spike_threshold_w
        self.window = window
        self.handoff_baselines = []
        self.baseline_mean = None
        self.prev_util = None
        self.handoff_detected = False
        self.post_handoff_buffer = collections.deque(maxlen=window)
        self.last_alert = None
        self.refire_after_s = refire_after_s

    def update(self, row):
        util = _f(row, 'utilization.gpu')
        power = _f(row, 'power.draw')
        if util is None or power is None:
            self.prev_util = util
            return None

        alert = None

        if self.prev_util is not None:
            if self.prev_util > 10 and util == 0:
                self.handoff_detected = True
                self.post_handoff_buffer.clear()
                if self.baseline_mean is None and len(self.handoff_baselines) < self.baseline_samples:
                    self.handoff_baselines.append(power)
                    if len(self.handoff_baselines) == self.baseline_samples:
                        self.baseline_mean = sum(self.handoff_baselines) / len(self.handoff_baselines)

            if self.handoff_detected and util > 10:
                self.post_handoff_buffer.append(power)
                if len(self.post_handoff_buffer) >= 10 and self.baseline_mean is not None:
                    resume_mean = sum(list(self.post_handoff_buffer)[:10]) / 10
                    delta = resume_mean - self.baseline_mean
                    if delta > self.spike_threshold:
                        now = time.time()
                        cooled_down = (self.last_alert is not None
                                        and (now - self.last_alert) < self.refire_after_s)
                        if not cooled_down:
                            self.last_alert = now
                            alert = {
                                'type': 'INTER_AGENT_HANDOFF_ANOMALY',
                                'severity': 'WARNING',
                                'gpu': row.get('index'),
                                'baseline_power_w': round(self.baseline_mean, 2),
                                'resume_power_w': round(resume_mean, 2),
                                'delta_w': round(delta, 2),
                                'timestamp': row.get('iso_timestamp'),
                                'message': (f"Agent resume power {resume_mean:.1f}W vs "
                                            f"baseline {self.baseline_mean:.1f}W "
                                            f"(+{delta:.1f}W) -- cause unconfirmed, "
                                            f"consistent with a workload change or a "
                                            f"compromised upstream agent"),
                            }
                    self.handoff_detected = False

        self.prev_util = util
        return alert
