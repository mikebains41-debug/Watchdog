"""LaserInjectionDetector timing, 2026-09-21. A controlled clock stands in for
the host's wall clock, so 'processed at 1 Hz' vs 'processed instantly' can be
compared on IDENTICAL data. A correct detector gives the same answer either way."""
import sys, types
from datetime import datetime, timedelta
sys.path.insert(0, '.')
import detection.hardware_attacks as ha
clock = [0.0]
ha.time = types.SimpleNamespace(time=lambda: clock[0], sleep=lambda s: None)
T0 = datetime(2026, 9, 21)

def run(temps, realtime):
    d = ha.LaserInjectionDetector()
    hits = []
    for k, t in enumerate(temps):
        clock[0] = float(k) if realtime else 0.0
        a = d.update({'index': 0, 'uuid': 'GPU-0', 'temperature.gpu': t,
                      'iso_timestamp': (T0 + timedelta(seconds=k)).isoformat()})
        if a:
            hits.append(a.get('temp_delta_c'))
    return hits or "none"

jump   = [45.0] * 5 + [50.0, 56.0, 57.0, 57.0, 57.0]
steady = [45.0, 45.4, 44.8, 45.3, 44.9, 45.2, 44.7, 45.1, 45.0, 44.8]
warmup = [45.0 + k for k in range(12)]
print("D1 real jump, processed at 1 Hz     :", run(jump, True),    "(expect alert)")
print("D2 real jump, processed instantly   :", run(jump, False),   "(expect alert)")
print("D3 steady +/-0.5C                   :", run(steady, True),  "(expect none)")
print("D4a normal warm-up 1C/s, at 1 Hz    :", run(warmup, True),  "(expect none)")
print("D4b normal warm-up, instantly       :", run(warmup, False), "(expect none)")
