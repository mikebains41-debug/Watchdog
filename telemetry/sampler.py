import time
from collections import deque


class DeltaTimedSampler:
    """
    Wraps a zero-argument sample_fn that returns one telemetry row (dict).
    Each call to sample() returns that row with 'actual_interval_ms' added:
    the measured wall-clock time since the previous sample, or None on the
    first sample (no prior reference exists yet).

    clock_fn defaults to time.perf_counter_ns and should not be overridden
    in production; the parameter exists so tests can inject a deterministic
    fake clock instead of depending on real elapsed time.
    """

    def __init__(self, sample_fn, history=1000, clock_fn=time.perf_counter_ns):
        self.sample_fn = sample_fn
        self.clock_fn = clock_fn
        self._last_ns = None
        self.deltas_ms = deque(maxlen=history)

    def sample(self):
        row = self.sample_fn()
        now_ns = self.clock_fn()

        if self._last_ns is None:
            row['actual_interval_ms'] = None
        else:
            delta_ms = (now_ns - self._last_ns) / 1_000_000
            row['actual_interval_ms'] = round(delta_ms, 3)
            self.deltas_ms.append(delta_ms)

        self._last_ns = now_ns
        return row

    def achieved_rate_hz(self):
        if not self.deltas_ms:
            return None
        mean_ms = sum(self.deltas_ms) / len(self.deltas_ms)
        if mean_ms <= 0:
            return None
        return round(1000.0 / mean_ms, 3)

    def stats(self):
        if not self.deltas_ms:
            return {'samples': 0, 'achieved_hz': None, 'min_ms': None,
                    'max_ms': None, 'mean_ms': None}
        vals = list(self.deltas_ms)
        return {
            'samples': len(vals),
            'achieved_hz': self.achieved_rate_hz(),
            'min_ms': round(min(vals), 3),
            'max_ms': round(max(vals), 3),
            'mean_ms': round(sum(vals) / len(vals), 3),
        }
