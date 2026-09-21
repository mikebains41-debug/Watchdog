#!/usr/bin/env python3
"""Tests for detection/fleet_health.py -- synthetic 8-GPU node, no hardware.
Negative controls must stay silent; positive controls must fire on the RIGHT GPU."""
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from detection.fleet_health import FleetHealthDetector  # noqa: E402

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("[%s] %s %s" % ("PASS" if cond else "FAIL", name, "" if cond else detail))


SLOT = [0, 0.5, 1, 1.5, 2, 2.5, 3, 4]


def node(steps=900, n=8, seed=3, fault=None):
    """Bursty serving, thermal lag, slot-position offsets (last cards run warmer)."""
    rng = random.Random(seed)
    busy, state = [], True
    while len(busy) < steps:
        busy += [state] * (rng.randint(8, 30) if state else rng.randint(3, 20))
        state = not state
    temp = [40.0] * n
    for i in range(steps):
        for g in range(n):
            u = (60 + rng.uniform(-8, 8)) if busy[i] else 0.0
            p = 126 + 524 * u / 100.0 + rng.uniform(-3, 3)
            temp[g] += ((38 + SLOT[g % 8] + 27 * (p - 126) / 524) - temp[g]) * 0.1
            P = {'index': g, 'uuid': 'GPU-%d' % g, 'power.draw': round(p, 1),
                 'temperature.gpu': round(temp[g], 1), 'utilization.gpu': round(u)}
            P = fault(g, i, P) if fault else P
            if P is not None:
                yield i, P


def run(fault=None, n=8, steps=900):
    d, hits = FleetHealthDetector(), []
    for i, P in node(steps=steps, n=n, fault=fault):
        a = d.update(P)
        while a:
            hits.append((a['type'], a['severity'], a['gpu'], i, a.get('room_wide_carve_out')))
            a = d._pending.pop(0) if d._pending else None
    return hits


def bump(g_sel, t0, dt):
    def f(g, i, P):
        if g == g_sel and i >= t0 and P['temperature.gpu'] is not None:
            P['temperature.gpu'] += dt
        return P
    return f


def main():
    print("=" * 60)
    print("FLEET HEALTH -- TESTS")
    print("=" * 60)

    check("negative: normal bursty serving on 8 GPUs, slot offsets -> silent", run() == [], str(run()))

    def room(g, i, P):
        if i >= 500:
            P['temperature.gpu'] += 6.0
        return P
    check("negative: whole room warms 6 C -> silent (room-wide change subtracted)", run(room) == [])

    h = run(lambda g, i, P: None if (g == 5 and i >= 400) else P)
    check("positive: GPU 5 stops reporting -> GPU_MISSING CRITICAL on GPU 5",
          h[:1] and h[0][0] == 'GPU_MISSING' and h[0][2] == 5, str(h))
    check("dead GPU caught within 6 polls", h[:1] and h[0][3] <= 406, str(h[:1]))

    def blank(g, i, P):
        if g == 4 and i >= 400:
            P['temperature.gpu'] = P['power.draw'] = None
        return P
    h = run(blank)
    check("positive: GPU 4 blank readings -> GPU_UNRESPONSIVE on GPU 4",
          any(x[0] == 'GPU_UNRESPONSIVE' and x[2] == 4 for x in h) and all(x[2] == 4 for x in h), str(h))

    def hot(g, i, P):
        if g == 2 and i >= 400:
            P['temperature.gpu'] = min(95.0, 60 + (i - 400) * 0.5)
        return P
    h = run(hot)
    check("positive: GPU 2 overheating -> GPU_THERMAL_EXTREME CRITICAL on GPU 2",
          any(x[0] == 'GPU_THERMAL_EXTREME' and x[1] == 'CRITICAL' and x[2] == 2 for x in h), str(h))
    check("overheating alerts name only GPU 2", h and all(x[2] == 2 for x in h), str(h))

    h = run(bump(6, 450, 12.0))
    check("positive: GPU 6 cooling degrades +12 C -> GPU_COOLING_DEGRADED on GPU 6 only",
          h and all(x[0] == 'GPU_COOLING_DEGRADED' and x[2] == 6 for x in h), str(h))

    def both(g, i, P):
        if i >= 450:
            P['temperature.gpu'] += 6.0
        if g == 6 and i >= 450:
            P['temperature.gpu'] += 12.0
        return P
    h = run(both)
    check("hard case: room +6 C AND GPU 6 degrades -> only GPU 6 flagged",
          h and all(x[2] == 6 for x in h), str(h))

    h = run(bump(1, 400, 12.0), n=2, steps=800)
    check("two GPUs only: degradation flagged, says room-wide change NOT ruled out",
          h[:1] and h[0][2] == 1 and h[0][4] is False, str(h))

    check("small change (+4 C) below the 8 C setting -> silent", run(bump(6, 450, 4.0)) == [])

    print("\n" + "=" * 60)
    print("PASSED: %d FAILED: %d" % (len(PASSED), len(FAILED)))
    for x in FAILED:
        print("  FAILED: %s" % x)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
