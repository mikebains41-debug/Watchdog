"""
detection/hashrate_correlation.py

Correlates externally-reported mining-pool hashrate against this GPU's
own power telemetry. Watchdog cannot see pool/hashrate data on its own --
the caller must supply it (e.g. from a pool API poll), same pattern as
ThroughputContentionDetector's calibrate()/process() split.

Turns "utilization looks mining-shaped" (CovertMiningDetector) into
"confirmed hashrate reported on this device", which is a materially
stronger claim -- but only when the caller has real pool data to feed in.

STILL UNRESOLVED, stated rather than hidden:
  Requires the caller to obtain hashrate data themselves; this module has
  no pool-API integration built in. Unvalidated against real hardware or
  a real pool.
"""
from detection._shared import _EventState, _f


class HashrateCorrelationDetector:
    def __init__(self, min_correlation_samples=10, power_per_hash_tolerance=0.25,
                 require_consecutive=3, refire_after_s=300):
        self.min_correlation_samples = min_correlation_samples
        self.power_per_hash_tolerance = power_per_hash_tolerance
        self.samples = []
        self.baseline_ratio = None
        self.state = _EventState(require_consecutive=require_consecutive,
                                  refire_after_s=refire_after_s)

    def calibrate(self, power_w, hashrate):
        if hashrate <= 0:
            return
        self.samples.append(power_w / hashrate)
        if len(self.samples) >= self.min_correlation_samples:
            vals = sorted(self.samples)
            self.baseline_ratio = vals[len(vals) // 2]

    def process(self, power_w, hashrate, gpu_index=0, timestamp=None):
        if self.baseline_ratio is None or hashrate <= 0:
            return None

        current_ratio = power_w / hashrate
        deviation = abs(current_ratio - self.baseline_ratio) / self.baseline_ratio

        condition = deviation > self.power_per_hash_tolerance
        if not self.state.should_emit(condition):
            return None

        return {
            'type': 'HASHRATE_POWER_MISMATCH',
            'severity': 'INFO',
            'gpu': gpu_index,
            'power_w': round(power_w, 2),
            'hashrate': hashrate,
            'watts_per_hash': round(current_ratio, 6),
            'baseline_watts_per_hash': round(self.baseline_ratio, 6),
            'deviation_pct': round(deviation * 100, 1),
            'timestamp': timestamp,
            'message': (f"Power-per-hash ratio deviated {deviation*100:.0f}% "
                        f"from this device's calibrated baseline -- "
                        f"efficiency change, algorithm switch, or "
                        f"reported-hashrate mismatch. Confirmed hashrate "
                        f"was supplied externally, not inferred."),
        }
