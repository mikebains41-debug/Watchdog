# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog engine tests: paired positive and negative controls.

A positive control alone proves nothing. Feeding a detector the exact
pattern it is coded to fire on will always pass, including when the
detector is wrong. Every positive control here has a negative control
next to it, drawn from states our own research documents as NORMAL:

  - idle floor          (80.36W H200, 67W A100 - cert sa-29820c)
  - cooldown tail       (147.96W decaying - cert sa-b2f092)
  - resident model      (memory allocated, process alive)
  - multi-GPU burst     (coordinated, architectural on A100 SXM / B200)

Run: python tests/test_engines.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.engines import (
    GhostPowerDetector,
    VRAMResidualDetector,
    VRAMResidualUnavailable,
    PowerPeriodicityDetector,
    MultiGPUCorrelation,
    DetectionPipeline,
)

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def row(power, util, mem, idx=0, temp=40, ts="2026-07-14T00:00:00", **kw):
    r = {
        'power.draw': power,
        'utilization.gpu': util,
        'memory.used': mem,
        'temperature.gpu': temp,
        'index': idx,
        'iso_timestamp': ts,
        'utilization.memory': 0,
    }
    r.update(kw)
    return r


def feed(det, rows):
    """Return every alert produced across a sequence."""
    out = []
    for r in rows:
        a = det.update(r)
        if a:
            out.append(a)
    return out


# ==========================================================================
# GhostPowerDetector
# ==========================================================================

def test_ghost_power_positive():
    """80W idle floor, then 150W at 0% util. Must fire."""
    d = GhostPowerDetector()
    baseline = [row(80.0 + (i % 3) * 0.5, 0, 100) for i in range(40)]
    ghost = [row(150.0, 0, 100) for _ in range(5)]
    alerts = feed(d, baseline + ghost)
    check("ghost_power POSITIVE: fires on 70W above floor",
          len(alerts) >= 1 and alerts[0]['type'] == 'GHOST_POWER',
          f"got {len(alerts)} alerts")
    if alerts:
        check("ghost_power POSITIVE: severity CRITICAL above 50W delta",
              alerts[0]['severity'] == 'CRITICAL',
              f"got {alerts[0]['severity']}")


def test_ghost_power_negative_idle():
    """Flat idle floor with normal jitter. Must NOT fire."""
    d = GhostPowerDetector()
    rows = [row(80.36 + (i % 5) * 0.4 - 0.8, 0, 100) for i in range(300)]
    alerts = feed(d, rows)
    check("ghost_power NEGATIVE: silent on clean idle",
          len(alerts) == 0,
          f"fired {len(alerts)} times on normal idle -- FALSE POSITIVE")


def test_ghost_power_negative_under_load():
    """High power while util is high. Not ghost power. Must NOT fire."""
    d = GhostPowerDetector()
    baseline = [row(80.0, 0, 100) for _ in range(40)]
    load = [row(520.0, 95, 40000) for _ in range(60)]
    alerts = feed(d, baseline + load)
    check("ghost_power NEGATIVE: silent under legitimate load",
          len(alerts) == 0,
          f"fired {len(alerts)} times at 95% util -- FALSE POSITIVE")


def test_ghost_power_edge_triggered():
    """A sustained 10-minute event must not emit 600 alerts."""
    d = GhostPowerDetector()
    baseline = [row(80.0, 0, 100) for _ in range(40)]
    sustained = [row(150.0, 0, 100) for _ in range(600)]
    alerts = feed(d, baseline + sustained)
    check("ghost_power: edge-triggered, not per-sample",
          len(alerts) <= 5,
          f"emitted {len(alerts)} alerts for one 600-sample event")


def test_ghost_power_baseline_not_poisoned():
    """A ghost event during baseline learning must not raise the floor.

    Median baseline: 40 idle samples at 80W, 15 contaminated at 150W.
    Median stays at 80W and the event still detects.
    """
    d = GhostPowerDetector()
    mixed = ([row(80.0, 0, 100) for _ in range(40)] +
             [row(150.0, 0, 100) for _ in range(15)])
    feed(d, mixed)
    check("ghost_power: median baseline resists contamination",
          d.baseline_w is not None and d.baseline_w < 100,
          f"baseline drifted to {d.baseline_w}W")


def test_ghost_power_handles_na():
    """nvidia-smi returns [N/A] on unsupported fields. Must not crash."""
    d = GhostPowerDetector()
    try:
        d.update(row('[N/A]', 0, 100))
        d.update(row(80.0, '[N/A]', 100))
        check("ghost_power: survives [N/A] fields", True)
    except Exception as e:
        check("ghost_power: survives [N/A] fields", False, f"raised {e!r}")


# ==========================================================================
# VRAMResidualDetector
# ==========================================================================

def test_vram_positive():
    """PID exits, 1200MB stays unclaimed. Must fire."""
    d = VRAMResidualDetector()
    rows = [
        row(300, 90, 1400, compute_apps=[{'pid': 1234, 'used_memory': 1200}]),
        row(300, 90, 1400, compute_apps=[{'pid': 1234, 'used_memory': 1200}]),
        row(85, 0, 1250, compute_apps=[]),   # pid gone, memory remains
        row(85, 0, 1250, compute_apps=[]),
    ]
    alerts = feed(d, rows)
    check("vram POSITIVE: fires when exited PID leaves memory allocated",
          len(alerts) >= 1 and alerts[0]['type'] == 'VRAM_RESIDUAL',
          f"got {len(alerts)} alerts")


def test_vram_negative_resident_model():
    """Model resident, process ALIVE. The commonest state in inference.

    The old detector fired CRITICAL here forever. This is the regression
    that matters most.
    """
    d = VRAMResidualDetector()
    rows = [row(85, 0, 40000,
                compute_apps=[{'pid': 999, 'used_memory': 39800}])
            for _ in range(200)]
    alerts = feed(d, rows)
    check("vram NEGATIVE: silent on resident model with live process",
          len(alerts) == 0,
          f"fired {len(alerts)} times on a live process -- FALSE POSITIVE")


def test_vram_negative_clean_exit():
    """PID exits AND memory is reclaimed. Must NOT fire."""
    d = VRAMResidualDetector()
    rows = [
        row(300, 90, 1400, compute_apps=[{'pid': 1234, 'used_memory': 1200}]),
        row(300, 90, 1400, compute_apps=[{'pid': 1234, 'used_memory': 1200}]),
        row(80, 0, 12, compute_apps=[]),     # reclaimed
        row(80, 0, 12, compute_apps=[]),
    ]
    alerts = feed(d, rows)
    check("vram NEGATIVE: silent when memory is properly reclaimed",
          len(alerts) == 0,
          f"fired {len(alerts)} times after clean reclaim -- FALSE POSITIVE")


def test_vram_refuses_without_pids():
    """Without compute_apps it must raise, not guess."""
    d = VRAMResidualDetector(strict=True)
    try:
        d.update(row(85, 0, 1250))
        check("vram: refuses to run without per-process data", False,
              "silently returned instead of raising")
    except VRAMResidualUnavailable:
        check("vram: refuses to run without per-process data", True)


# ==========================================================================
# PowerPeriodicityDetector
# ==========================================================================

def test_periodicity_positive():
    """A genuine square wave: 20 samples high, 20 low. Must fire.

    The old reversal-counting metric was BLIND to this.
    """
    d = PowerPeriodicityDetector()
    rows = []
    for i in range(400):
        p = 120.0 if (i // 20) % 2 == 0 else 90.0
        rows.append(row(p, 0, 100))
    alerts = feed(d, rows)
    check("periodicity POSITIVE: fires on 40-sample square wave",
          len(alerts) >= 1 and alerts[0]['type'] == 'POWER_PERIODICITY',
          f"got {len(alerts)} alerts (old metric scored this LOW)")
    if alerts:
        check("periodicity POSITIVE: recovers period near 40",
              30 <= alerts[0]['period_samples'] <= 50,
              f"got lag {alerts[0]['period_samples']}")


def test_periodicity_negative_jitter():
    """Alternating +-1W idle noise. Must NOT fire.

    The old metric scored this ~1.0 and fired CRITICAL.
    """
    d = PowerPeriodicityDetector()
    rows = [row(80.0 + (1.0 if i % 2 == 0 else -1.0), 0, 100)
            for i in range(400)]
    alerts = feed(d, rows)
    check("periodicity NEGATIVE: silent on +-1W alternating jitter",
          len(alerts) == 0,
          f"fired {len(alerts)} times on noise -- FALSE POSITIVE")


def test_periodicity_negative_flat():
    """Dead flat power. Must NOT fire (and must not divide by zero)."""
    d = PowerPeriodicityDetector()
    alerts = feed(d, [row(80.0, 0, 100) for _ in range(400)])
    check("periodicity NEGATIVE: silent on flat power",
          len(alerts) == 0,
          f"fired {len(alerts)} times on constant input")


# ==========================================================================
# MultiGPUCorrelation
# ==========================================================================

def test_correlation_is_info_only():
    """Coordinated multi-GPU bursts are architectural, not attack."""
    c = MultiGPUCorrelation()
    c.add_alert({'type': 'GHOST_POWER', 'gpu': 0})
    result = c.add_alert({'type': 'GHOST_POWER', 'gpu': 1})
    check("correlation: severity is INFO, not EMERGENCY",
          result is not None and result['severity'] == 'INFO',
          f"got {result['severity'] if result else 'None'}")


# ==========================================================================
# Pipeline
# ==========================================================================

def test_pipeline_negative_control():
    """THE headline number: clean idle GPU, one hour at 1Hz, zero alerts.

    This is what nobody else in GPU security publishes.
    """
    p = DetectionPipeline(vram_strict=False)
    for i in range(3600):
        p.process(row(80.36 + (i % 7) * 0.3 - 0.9, 0, 100,
                      compute_apps=[]))
    s = p.stats()
    check("PIPELINE NEGATIVE CONTROL: 3600 clean idle samples, 0 alerts",
          s['alerts'] == 0,
          f"emitted {s['alerts']} alerts -- alerts_per_sample={s['alerts_per_sample']}")
    print(f"       stats: {s}")


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for t in tests:
        try:
            t()
        except Exception as e:
            check(t.__name__, False, f"EXCEPTION {e!r}")

    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print("\nFailures:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
