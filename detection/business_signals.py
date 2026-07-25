import time, collections
from detection._shared import _EventState, _f


class CovertMiningDetector:
    """
    Detects sustained, unauthorized crypto-mining-pattern usage: very high
    utilization held essentially flat for a long duration, with power
    tracking near the board's TDP ceiling -- a signature distinct from
    normal ML training/inference, which has natural variance from batch
    boundaries, checkpointing, data loading stalls, and mixed precision
    shifts.

    This is a market-framing sibling of AgentOrchestrationAnomalyDetector
    (detection/llm_attacks.py), not a replacement -- that detector catches
    power elevated while utilization claims idle (covert background
    activity); this one catches the opposite shape: utilization genuinely
    high, but suspiciously FLAT for far longer than legitimate workloads
    typically run unbroken, which is the actual signature operators use to
    spot unauthorized miners on shared/rented infrastructure.

    STILL UNRESOLVED, stated rather than hidden:
      This cannot distinguish authorized mining (a tenant who legitimately
      rented the GPU to mine) from unauthorized mining (an employee or a
      guest process doing it without permission). That distinction requires
      a policy signal this detector has no access to -- e.g. an allowlist
      of authorized workload types per tenant. This detector answers "is
      mining-shaped activity happening," not "is it authorized."

      Also unvalidated against real hardware: the flat-utilization and
      TDP-ceiling thresholds below are reasonable starting points, not
      measured constants. They should be tuned once real mining vs. real
      training telemetry exists to compare against.
    """

    def __init__(self, util_floor_pct=95.0, tdp_ceiling_fraction=0.90,
                 variance_ceiling_pct=3.0, min_duration_samples=600,
                 require_consecutive=1, refire_after_s=300):
        self.util_floor_pct = util_floor_pct
        self.tdp_ceiling_fraction = tdp_ceiling_fraction
        self.variance_ceiling_pct = variance_ceiling_pct
        self.min_duration_samples = min_duration_samples
        self.util_history = collections.deque(maxlen=min_duration_samples)
        self.power_history = collections.deque(maxlen=min_duration_samples)
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def update(self, row):
        util = _f(row, 'utilization.gpu')
        power = _f(row, 'power.draw')
        power_limit = _f(row, 'power.limit')
        if util is None or power is None or power_limit is None or power_limit <= 0:
            return None

        self.util_history.append(util)
        self.power_history.append(power)

        if len(self.util_history) < self.min_duration_samples:
            return None

        utils = list(self.util_history)
        powers = list(self.power_history)

        avg_util = sum(utils) / len(utils)
        util_variance = max(utils) - min(utils)
        avg_power_fraction = (sum(powers) / len(powers)) / power_limit

        condition = (avg_util >= self.util_floor_pct
                     and util_variance <= self.variance_ceiling_pct
                     and avg_power_fraction >= self.tdp_ceiling_fraction)

        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'COVERT_MINING_PATTERN',
            'severity': 'WARNING',
            'gpu': row.get('index'),
            'avg_utilization_pct': round(avg_util, 2),
            'utilization_variance_pct': round(util_variance, 2),
            'avg_power_fraction_of_tdp': round(avg_power_fraction, 3),
            'duration_samples': len(utils),
            'timestamp': row.get('iso_timestamp'),
            'message': (f"Sustained {avg_util:.1f}% utilization, essentially "
                        f"flat (variance {util_variance:.1f}%), at "
                        f"{avg_power_fraction*100:.0f}% of TDP for "
                        f"{len(utils)} consecutive samples -- consistent "
                        f"with unattended mining-pattern load. This does "
                        f"NOT confirm the activity is unauthorized -- only "
                        f"that its shape differs from typical variable ML "
                        f"training/inference workloads."),
        }


class BillingIntegrityDetector:
    """
    Flags a mismatch between what a GPU cloud reports for billing
    (utilization.gpu) and what the hardware's own power telemetry shows --
    i.e. the ghost-power finding, reframed as a billing-integrity check
    rather than a security check.

    Same underlying signal as GhostPowerDetector in detection/engines.py.
    Kept as a separate class (not merged) because the audience and message
    framing are different: GhostPowerDetector is written for a security
    operator ("is something hiding from telemetry"); this one is written
    for a billing/finance audience ("does what we're being charged/billed
    match what the hardware actually did"), and produces a
    dollar-estimable delta rather than a security alert.

    STILL UNRESOLVED, stated rather than hidden:
      This only detects that idle-labeled time carried non-trivial power
      draw -- it does NOT independently know the provider's billing rate
      or billing model (some bill flat per-GPU-hour regardless of
      utilization, in which case this signal is not a billing problem at
      all). estimated_cost_impact below requires the caller to supply a
      known $/kWh or $/GPU-hour rate; without one, only the physical
      wattage delta is reported, no dollar figure is invented.
    """

    def __init__(self, ghost_threshold_w=15.0, baseline_min_samples=30,
                 baseline_window=300, require_consecutive=5,
                 refire_after_s=120, rate_usd_per_kwh=None):
        self.ghost_threshold_w = ghost_threshold_w
        self.baseline_min_samples = baseline_min_samples
        self.idle_samples = collections.deque(maxlen=baseline_window)
        self.baseline_idle_w = None
        self.rate_usd_per_kwh = rate_usd_per_kwh
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)
        self._ghost_seconds_accum = 0.0
        self._ghost_watt_seconds_accum = 0.0
        self._last_ts = None

    def update(self, row, now=None):
        power = _f(row, 'power.draw')
        util = _f(row, 'utilization.gpu')
        if power is None or util is None:
            return None

        t = now if now is not None else time.time()
        dt = 0.0
        if self._last_ts is not None:
            dt = max(0.0, t - self._last_ts)
        self._last_ts = t

        if self.baseline_idle_w is None:
            if util == 0:
                self.idle_samples.append(power)
            if len(self.idle_samples) >= self.baseline_min_samples:
                vals = sorted(self.idle_samples)
                self.baseline_idle_w = vals[len(vals) // 2]
            return None

        if util != 0:
            return None

        ghost_w = power - self.baseline_idle_w
        condition = ghost_w > self.ghost_threshold_w

        if condition:
            self._ghost_seconds_accum += dt
            self._ghost_watt_seconds_accum += ghost_w * dt

        if not self.state.should_emit(condition):
            return None

        est_cost = None
        if self.rate_usd_per_kwh is not None:
            kwh = self._ghost_watt_seconds_accum / 3600.0 / 1000.0
            est_cost = round(kwh * self.rate_usd_per_kwh, 4)

        return {
            'type': 'BILLING_INTEGRITY_GAP',
            'severity': 'INFO',
            'gpu': row.get('index'),
            'reported_utilization_pct': util,
            'power_w': round(power, 2),
            'baseline_idle_w': round(self.baseline_idle_w, 2),
            'ghost_power_w': round(ghost_w, 2),
            'cumulative_ghost_seconds': round(self._ghost_seconds_accum, 1),
            'estimated_cost_usd': est_cost,
            'timestamp': row.get('iso_timestamp'),
            'message': (f"GPU reports {util:.0f}% utilization (billed as "
                        f"idle) but drew {ghost_w:.1f}W above this "
                        f"device's own learned idle floor -- a billing "
                        f"metering question, not necessarily a security "
                        f"one. Does not know your billing model; only the "
                        f"physical wattage gap is measured"
                        + (f", estimated at ${est_cost} so far at the "
                           f"supplied rate." if est_cost is not None
                           else "; no cost rate supplied.")),
        }
