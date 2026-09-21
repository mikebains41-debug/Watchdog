# Author: Manmohan (Mike) Bains -- Watchdog
import collections, time
from datetime import datetime
from detection._shared import _f


class FanWearDetector:
    # Note: sustained high temp with suppressed fan response has a
    # second real-world cause beyond hardware wear -- mining malware
    # is documented to deliberately reduce fan speed to avoid
    # triggering overheating alarms while hiding covert compute.
    # Same signal, an additional motive; not yet distinguished here.
    def __init__(self, window=200):
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.last_alert = None
    def update(self, row):
        temp = _f(row, 'temperature.gpu')
        util = _f(row, 'utilization.gpu')
        if temp is None or util is None: return None
        self.history.append({'temp':temp,'util':util})
        if len(self.history) < self.window: return None
        vals = list(self.history)
        high_util_high_temp = [v for v in vals if v['util'] > 50 and v['temp'] > 80]
        if len(high_util_high_temp) > self.window * 0.7:
            now = time.time()
            if self.last_alert and now-self.last_alert < 300: return None
            self.last_alert = now
            avg_temp = sum(v['temp'] for v in high_util_high_temp)/len(high_util_high_temp)
            return {'type':'FAN_WEAR_PREDICTED','severity':'WARNING','gpu':row.get('index'),'avg_temp_c':round(avg_temp,1),'timestamp':row.get('iso_timestamp'),'message':f"Sustained high temp {avg_temp:.1f}C under load — possible cooling degradation"}
        return None
class CapacitorAgingDetector:
    def __init__(self, window=300):
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.last_alert = None
    def update(self, row):
        power = _f(row, 'power.draw')
        util = _f(row, 'utilization.gpu')
        if power is None or util is None: return None
        self.history.append({'power':power,'util':util})
        if len(self.history) < self.window: return None
        vals = [v for v in self.history if v['util'] > 40]
        if len(vals) < 50: return None
        powers = [v['power'] for v in vals]
        ripple = max(powers) - min(powers)
        mean_power = sum(powers)/len(powers)
        ripple_pct = (ripple/mean_power*100) if mean_power > 0 else 0
        if ripple_pct > 20:
            now = time.time()
            if self.last_alert and now-self.last_alert < 300: return None
            self.last_alert = now
            return {'type':'CAPACITOR_AGING_PREDICTED','severity':'WARNING','gpu':row.get('index'),'ripple_pct':round(ripple_pct,1),'timestamp':row.get('iso_timestamp'),'message':f"Power ripple {ripple_pct:.1f}% under sustained load — possible PSU capacitor aging"}
        return None
class PackageCrackingDetector:
    """Thermal-cycling exposure (formerly 'package crack predicted').

    REDESIGNED 2026-09-21. The old check warned 'possible solder joint fatigue'
    whenever temperature varied more than 8 C across busy samples in a
    100-sample window -- i.e. on every warm-up. scripts/repro_moe_multi_gpu.py
    showed it firing on every GPU under steady load, and its own regression
    test's 'positive control' was a single 70 -> 85 C step. Solder-joint
    fatigue is driven by repeated thermal CYCLES -- heating then cooling, many
    times -- with damage accumulating over months. One warm-up is half of one
    cycle.

    Now: counts completed heat/cool swings of at least `cycle_c` (default 10 C,
    with hysteresis) over the last `window` samples (default 3600: one hour at
    1 Hz), and reports THERMAL_CYCLING_EXPOSURE at INFO once full cycles reach
    `cycles_threshold` (default 20). Telemetry cannot see a crack: this is an
    exposure measure for maintenance planning, not a failure prediction. The
    thresholds are NOT validated against failure data for any GPU. Counts
    samples, not wall-clock time.
    """

    def __init__(self, window=3600, cycle_c=10.0, cycles_threshold=20, refire_samples=None):
        self.window = window
        self.cycle_c = cycle_c
        self.cycles_threshold = cycles_threshold
        self.refire_samples = refire_samples if refire_samples is not None else window
        self.n = 0
        self.anchor = None      # last confirmed turning point
        self.ext = None         # running extreme since the anchor
        self.state = None       # 'up', 'down' or None (direction not yet established)
        self.swings = collections.deque()   # (sample index, amplitude) of confirmed half-cycles
        self.since_fire = None

    def _confirm(self, amplitude):
        self.swings.append((self.n, amplitude))

    def update(self, row):
        temp = _f(row, 'temperature.gpu')
        if temp is None:
            return None
        self.n += 1
        if self.since_fire is not None:
            self.since_fire += 1
        if self.anchor is None:
            self.anchor = self.ext = temp
            return None
        if self.state is None:
            if temp - self.anchor >= self.cycle_c:
                self.state, self.ext = 'up', temp
            elif self.anchor - temp >= self.cycle_c:
                self.state, self.ext = 'down', temp
        elif self.state == 'up':
            if temp > self.ext:
                self.ext = temp
            elif self.ext - temp >= self.cycle_c:
                self._confirm(self.ext - self.anchor)
                self.anchor, self.state, self.ext = self.ext, 'down', temp
        else:
            if temp < self.ext:
                self.ext = temp
            elif temp - self.ext >= self.cycle_c:
                self._confirm(self.anchor - self.ext)
                self.anchor, self.state, self.ext = self.ext, 'up', temp
        while self.swings and self.n - self.swings[0][0] > self.window:
            self.swings.popleft()
        cycles = len(self.swings) // 2
        if cycles < self.cycles_threshold:
            return None
        if self.since_fire is not None and self.since_fire < self.refire_samples:
            return None
        self.since_fire = 0
        mean_amp = sum(a for _, a in self.swings) / len(self.swings)
        return {
            'type': 'THERMAL_CYCLING_EXPOSURE',
            'severity': 'INFO',
            'gpu': row.get('index'),
            'cycles': cycles,
            'window_samples': self.window,
            'mean_swing_c': round(mean_amp, 1),
            'timestamp': row.get('iso_timestamp'),
            'message': ("%d thermal cycles of at least %.0f C (mean swing %.1f C) in the last %d "
                        "samples. Repeated cycling accumulates solder-joint fatigue over time; "
                        "this is an exposure measure, not a crack prediction. Threshold "
                        "unvalidated for any specific GPU." % (cycles, self.cycle_c, mean_amp, self.window)),
        }
