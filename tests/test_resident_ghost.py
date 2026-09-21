#!/usr/bin/env python3
"""Tests for ResidentGhostPowerDetector (detection/engines.py) and
FullDetectionPipeline._reclassify_resident_prediction (watchdog.py).
Synthetic rows only; no GPU needed."""
import os
import sys
import types
import contextlib
import io

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from detection.engines import ResidentGhostPowerDetector  # noqa: E402

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("[%s] %s %s" % ("PASS" if cond else "FAIL", name, "" if cond else detail))


def row(p, u, m, i=0):
    return {'index': i, 'power.draw': p, 'utilization.gpu': u, 'memory.used': m,
            'iso_timestamp': '2026-09-21T00:00:00'}


def learned(n=40, p=126.0):
    d = ResidentGhostPowerDetector()
    for k in range(n):
        d.update(row(p + (k % 5 - 2) * 0.8, 0, 68000))
    return d


def main():
    print("=" * 60)
    print("RESIDENT GHOST POWER -- TESTS")
    print("=" * 60)

    d = learned()
    check("learns this GPU's loaded-idle floor (~126 W)", d.floor_w is not None and 124 < d.floor_w < 128,
          str(d.floor_w))
    hits = [d.update(row(126.0 + (k % 7 - 3), 0, 68000)) for k in range(200)]
    check("negative control: loaded idle stays silent", not any(hits))

    d = learned()
    tail = [147.96 - 22 * (1 - 0.7 ** k) for k in range(30)]
    check("negative control: README cooldown tail (148 W decaying) silent",
          not any(d.update(row(p, 0, 68000)) for p in tail))

    d = learned()
    check("busy at 650 W / 95% util silent",
          not any(d.update(row(650, 95, 68000)) for _ in range(60)))

    d = learned()
    hits = [d.update(row(450, 0, 68000)) for _ in range(20)]
    first = next((k for k, h in enumerate(hits) if h), None)
    check("positive control: 450 W at 0% util on a loaded GPU fires", first is not None)
    check("fires only after sustained excess (10 samples, not 1)", first == 9, "first=%s" % first)
    a = hits[first] if first is not None else {}
    check("alert names its baseline and what it cannot distinguish",
          a.get('type') == 'GHOST_POWER_RESIDENT' and a.get('loaded_idle_floor_w') and a.get('cannot_distinguish'))

    d = learned()
    n = sum(1 for _ in range(250) if d.update(row(450, 0, 68000)))
    check("does not re-fire every sample (sample-count refire, not wall clock)", n == 1, "fired %d" % n)

    d = ResidentGhostPowerDetector()
    check("no model loaded: not this detector's job, no floor, silent",
          not any(d.update(row(450, 0, 1)) for _ in range(80)) and d.floor_w is None)

    d = ResidentGhostPowerDetector()
    check("no floor yet: silent (stated limitation, not a pass)",
          not any(d.update(row(450, 0, 68000)) for _ in range(20)))

    with contextlib.redirect_stdout(io.StringIO()):
        import watchdog
    f = watchdog.FullDetectionPipeline._reclassify_resident_prediction
    pred = {'type': 'GHOST_POWER_PREDICTED', 'severity': 'WARNING', 'gpu': 3, 'current_power_w': 130.0}
    loaded = types.SimpleNamespace(_last_row_by_gpu={'3': {'memory.used': 68000}})
    empty = types.SimpleNamespace(_last_row_by_gpu={'3': {'memory.used': 1}})
    out = f(loaded, dict(pred))
    check("prediction on a LOADED GPU -> IDLE_RESIDENT_ENERGY INFO, origin recorded",
          out['type'] == 'IDLE_RESIDENT_ENERGY' and out['severity'] == 'INFO'
          and out['reclassified_from'] == 'GHOST_POWER_PREDICTED')
    check("prediction on an EMPTY GPU unchanged", f(empty, dict(pred))['type'] == 'GHOST_POWER_PREDICTED')
    check("unknown GPU unchanged", f(types.SimpleNamespace(), dict(pred))['type'] == 'GHOST_POWER_PREDICTED')
    other = {'type': 'THERMAL_EVENT_PREDICTED', 'gpu': 3}
    check("other alert types untouched", f(loaded, dict(other)) == other)

    print("\n" + "=" * 60)
    print("PASSED: %d FAILED: %d" % (len(PASSED), len(FAILED)))
    for x in FAILED:
        print("  FAILED: %s" % x)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
