#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_new_detectors.py

Tests for the three detectors added to close gaps identified against
published GPU attack research:

  ECCAnomalyDetector          -- GPUHammer / Rowhammer bit-flip signature
  ThermalSideChannelDetector  -- Hot Pixels (USENIX Sec 2023) thermal channel
  PCIeAnomalyDetector         -- Invisible Probe / LockedDown PCIe channel

Every detector here has BOTH positive and negative controls. The
negative controls matter more: a detector that fires on a healthy GPU,
a busy GPU, or a legitimate data transfer is worse than no detector.

Run: python3 tests/test_new_detectors.py
"""

import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.hardware_attacks import (
    ECCAnomalyDetector, ECCUnavailable,
    ThermalSideChannelDetector,
    PCIeAnomalyDetector, PCIeTelemetryUnavailable,
)

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    if cond:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def ts(i):
    return (datetime(2026, 8, 1) + timedelta(seconds=i)).isoformat()


def ecc_row(i, corrected, uncorrected=0, idx=0):
    return {'index': idx, 'iso_timestamp': ts(i),
            'ecc.errors.corrected.volatile.total': corrected,
            'ecc.errors.uncorrected.volatile.total': uncorrected}


def th_row(i, temp, util, idx=0):
    return {'index': idx, 'iso_timestamp': ts(i),
            'temperature.gpu': temp, 'utilization.gpu': util}


def pcie_row(i, rx, tx, util, idx=0):
    return {'index': idx, 'iso_timestamp': ts(i), 'utilization.gpu': util,
            'pcie_rx_mbs': rx, 'pcie_tx_mbs': tx}


# ---------------------------------------------------------------- ECC

def test_ecc_strict_refuses_without_fields():
    d = ECCAnomalyDetector(strict=True)
    try:
        d.update({'index': 0, 'iso_timestamp': ts(0)})
        check("ECC: strict raises when ECC fields absent", False, "no raise")
    except ECCUnavailable:
        check("ECC: strict raises when ECC fields absent", True)


def test_ecc_nonstrict_silent_without_fields():
    d = ECCAnomalyDetector(strict=False)
    r = d.update({'index': 0, 'iso_timestamp': ts(0)})
    check("ECC: non-strict returns None when fields absent", r is None)


def test_ecc_uncorrectable_fires_immediately():
    d = ECCAnomalyDetector()
    r = d.update(ecc_row(0, 0, uncorrected=1))
    check("ECC POSITIVE: uncorrectable fires immediately at CRITICAL",
          r is not None and r['type'] == 'ECC_UNCORRECTABLE'
          and r['severity'] == 'CRITICAL', f"got {r}")


def test_ecc_negative_flat_counter():
    d = ECCAnomalyDetector(baseline_min_samples=5, require_consecutive=2)
    fired = [a for a in (d.update(ecc_row(i, 0)) for i in range(40)) if a]
    check("ECC NEGATIVE: silent on a flat (healthy) corrected counter",
          len(fired) == 0, f"fired {len(fired)}x -- FALSE POSITIVE")


def test_ecc_negative_steady_background_rate():
    d = ECCAnomalyDetector(baseline_min_samples=8, require_consecutive=3,
                            corrected_rate_threshold=1.0)
    c, alerts = 0, []
    for i in range(40):
        c += 1
        alerts.append(d.update(ecc_row(i, c)))
    fired = [a for a in alerts if a]
    check("ECC NEGATIVE: silent on steady low background rate",
          len(fired) == 0, f"fired {len(fired)}x -- FALSE POSITIVE")


def test_ecc_positive_rate_spike():
    d = ECCAnomalyDetector(baseline_min_samples=8, require_consecutive=3,
                            corrected_rate_threshold=1.0)
    c = 0
    for i in range(15):
        c += 1
        d.update(ecc_row(i, c))
    alerts = []
    for i in range(15, 30):
        c += 50
        alerts.append(d.update(ecc_row(i, c)))
    fired = [a for a in alerts if a]
    check("ECC POSITIVE: fires on a sustained corrected-rate spike",
          bool(fired) and fired[0]['type'] == 'ECC_CORRECTED_RATE_ANOMALY',
          f"got {len(fired)} fired")
    if fired:
        check("ECC POSITIVE: reports a sane per-second rate, not a raw counter",
              fired[0]['corrected_rate_per_s'] < 1000,
              f"got {fired[0]['corrected_rate_per_s']}")


def test_ecc_message_discloses_alternatives():
    d = ECCAnomalyDetector(baseline_min_samples=5, require_consecutive=2,
                            corrected_rate_threshold=1.0)
    c, fired = 0, None
    for i in range(10):
        c += 1
        d.update(ecc_row(i, c))
    for i in range(10, 25):
        c += 50
        r = d.update(ecc_row(i, c))
        if r and not fired:
            fired = r
    check("ECC: message discloses non-attack causes honestly",
          bool(fired) and 'unconfirmed' in fired['message']
          and 'cosmic' in fired['message'],
          f"got {fired['message'] if fired else 'no alert'}")


# ------------------------------------------------------------ THERMAL

def test_thermal_negative_stable_idle():
    d = ThermalSideChannelDetector(baseline_min_samples=10,
                                    require_consecutive=3)
    fired = [a for a in (d.update(th_row(i, 40 + (i % 3), 0))
                          for i in range(60)) if a]
    check("THERMAL NEGATIVE: silent on stable idle temperature",
          len(fired) == 0, f"fired {len(fired)}x -- FALSE POSITIVE")


def test_thermal_negative_hot_but_busy():
    d = ThermalSideChannelDetector(baseline_min_samples=10,
                                    require_consecutive=3)
    for i in range(20):
        d.update(th_row(i, 40, 0))
    fired = [a for a in (d.update(th_row(i, 85, 95))
                          for i in range(20, 50)) if a]
    check("THERMAL NEGATIVE: silent when the GPU is genuinely busy",
          len(fired) == 0, f"fired {len(fired)}x -- FALSE POSITIVE")


def test_thermal_positive_hot_while_idle():
    d = ThermalSideChannelDetector(baseline_min_samples=10,
                                    require_consecutive=3,
                                    temp_delta_threshold=8.0)
    for i in range(20):
        d.update(th_row(i, 40, 0))
    fired = [a for a in (d.update(th_row(i, 58, 2))
                          for i in range(20, 40)) if a]
    check("THERMAL POSITIVE: fires when hot at low local compute",
          bool(fired) and fired[0]['type'] == 'THERMAL_UTILIZATION_DECOUPLING',
          f"got {len(fired)} fired")
    if fired:
        check("THERMAL: severity is INFO, not an attack claim",
              fired[0]['severity'] == 'INFO', f"got {fired[0]['severity']}")
        check("THERMAL: message states plainly that no data is recovered",
              'no data is recovered' in fired[0]['message'])


# --------------------------------------------------------------- PCIE

def test_pcie_strict_refuses_without_fields():
    d = PCIeAnomalyDetector(strict=True)
    try:
        d.update({'index': 0, 'iso_timestamp': ts(0), 'utilization.gpu': 0})
        check("PCIE: strict raises when PCIe fields absent", False, "no raise")
    except PCIeTelemetryUnavailable:
        check("PCIE: strict raises when PCIe fields absent", True)


def test_pcie_negative_low_idle_traffic():
    d = PCIeAnomalyDetector(baseline_min_samples=8, require_consecutive=3)
    fired = [a for a in (d.update(pcie_row(i, 4 + (i % 3), 3, 0))
                          for i in range(40)) if a]
    check("PCIE NEGATIVE: silent on low idle bus traffic",
          len(fired) == 0, f"fired {len(fired)}x -- FALSE POSITIVE")


def test_pcie_negative_busy_transfer():
    d = PCIeAnomalyDetector(baseline_min_samples=8, require_consecutive=3)
    for i in range(15):
        d.update(pcie_row(i, 4, 3, 0))
    fired = [a for a in (d.update(pcie_row(i, 4000, 2000, 92))
                          for i in range(15, 40)) if a]
    check("PCIE NEGATIVE: silent on heavy transfer during heavy compute",
          len(fired) == 0, f"fired {len(fired)}x -- FALSE POSITIVE")


def test_pcie_positive_transfer_at_idle():
    d = PCIeAnomalyDetector(baseline_min_samples=8, require_consecutive=3,
                             throughput_threshold_mbs=100.0)
    for i in range(15):
        d.update(pcie_row(i, 4, 3, 0))
    fired = [a for a in (d.update(pcie_row(i, 900, 700, 2))
                          for i in range(15, 40)) if a]
    check("PCIE POSITIVE: fires on bulk transfer at low compute",
          bool(fired) and fired[0]['type'] == 'PCIE_TRANSFER_AT_LOW_COMPUTE',
          f"got {len(fired)} fired")
    if fired:
        check("PCIE: message discloses benign explanations",
              'checkpointing' in fired[0]['message'])


if __name__ == '__main__':
    for _name, _fn in sorted(list(globals().items())):
        if _name.startswith('test_'):
            try:
                _fn()
            except Exception as e:
                check(_name, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print("\nFailures:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
