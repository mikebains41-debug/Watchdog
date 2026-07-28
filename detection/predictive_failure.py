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
    def __init__(self, window=100):
        self.window = window
        self.history = collections.deque(maxlen=window)
        self.last_alert = None
    def update(self, row):
        temp = _f(row, 'temperature.gpu')
        util = _f(row, 'utilization.gpu')
        if temp is None or util is None: return None
        self.history.append({'temp':temp,'util':util,'ts':time.time()})
        if len(self.history) < self.window: return None
        vals = list(self.history)
        high_util = [v for v in vals if v['util'] > 60]
        if len(high_util) < 20: return None
        temps = [v['temp'] for v in high_util]
        temp_delta = max(temps) - min(temps)
        if temp_delta > 8:
            now = time.time()
            if self.last_alert and now-self.last_alert < 300: return None
            self.last_alert = now
            return {'type':'PACKAGE_CRACK_PREDICTED','severity':'WARNING','gpu':row.get('index'),'temp_delta_c':round(temp_delta,1),'timestamp':row.get('iso_timestamp'),'message':f"Junction temp delta {temp_delta:.1f}C under sustained load — possible solder joint fatigue"}
        return None
