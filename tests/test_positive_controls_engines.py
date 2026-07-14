#!/usr/bin/env python3
# Watchdog AIDR
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer / Watchdog
#
# Positive Control Tests: detection/engines.py (7 detectors)
# ==============================================================
# WHY THIS EXISTS
#   validation_results/SUMMARY.md states plainly: "the Watchdog detector
#   CODE has not yet proven it can detect anything... still unvalidated
#   after" -- 0 alerts fired on both baseline and simulated-contention
#   test data across all 24 engines.
#
#   A "0 alerts" result is only meaningful if the detector is PROVEN
#   capable of firing on a known-positive signal. This file closes that
#   gap for the 7 detectors in detection/engines.py, using synthetic
#   input sequences engineered from each detector's EXACT source logic.
#
# WHAT SUCCESS LOOKS LIKE
#   Each detector fires when fed a sequence engineered to match its real
#   trigger condition, AND stays silent on a clean sequence.
#
# HONEST STATUS
#   Verified locally against a copy of the real engines.py logic
#   (9/9 tests passing) before being handed off for on-device
#   confirmation against the actual repo code.

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
from engines import (
    GhostPowerDetector,
    VRAMResidualDetector,
    PowerSideChannelDetector,
    ThermalEmanationDetector,
    CrossTenantBleedingDetector,
    TimingCovertChannelDetector,
    CrossWorkloadClusteringDetector,
)


def make_row(power=0, util=0, mem=0, temp=40, index=0):
    """Builds a synthetic telemetry row matching the real .get() field
    names used throughout engines.py."""
    return {
        "power.draw": power,
        "utilization.gpu": util,
        "memory.used": mem,
        "temperature.gpu": temp,
        "iso_timestamp": "2026-01-01T00:00:00Z",
        "index": index,
    }


def test_ghost_power_detector():
    """
    Real trigger: needs window=30 samples to fill history, >=10 of those
    idle (util==0, mem<500) to set baseline_w, then a sample with util==0
    and power > baseline_w + threshold_w(15) fires GHOST_POWER.
    """
    d = GhostPowerDetector()
    for _ in range(30):
        d.update(make_row(power=50, util=0, mem=100))
    result = d.update(make_row(power=100, util=0, mem=100))
    assert result is not None and result["type"] == "GHOST_POWER", \
        "FAIL: GhostPowerDetector did not fire on known ghost-power pattern"
    print(f"[PASS] GhostPowerDetector fired correctly: {result['message']}")


def test_vram_residual_detector():
    """
    Real trigger: a prior sample with util>10 sets last_util, THEN a
    sample with util==0 and mem > threshold_mb(100) fires VRAM_RESIDUAL.
    """
    d = VRAMResidualDetector()
    d.update(make_row(power=200, util=80, mem=8000))
    result = d.update(make_row(power=50, util=0, mem=500))
    assert result is not None and result["type"] == "VRAM_RESIDUAL", \
        "FAIL: VRAMResidualDetector did not fire on known residual pattern"
    print(f"[PASS] VRAMResidualDetector fired correctly: {result['message']}")


def test_power_side_channel_detector():
    """
    Real trigger: window=200 samples with power oscillation amplitude
    >= min_amplitude*2(10W) and >30% of samples showing >5W transitions.
    """
    d = PowerSideChannelDetector()
    result = None
    for i in range(200):
        power = 100 if i % 2 == 0 else 120
        result = d.update(make_row(power=power, util=50, mem=1000)) or result
    assert result is not None and result["type"] == "POWER_SIDE_CHANNEL", \
        "FAIL: PowerSideChannelDetector did not fire on known oscillation"
    print(f"[PASS] PowerSideChannelDetector fired correctly: {result['message']}")


def test_thermal_emanation_detector():
    """
    Real trigger: last 10 samples show temp gradient > 5.0C while util<10.
    """
    d = ThermalEmanationDetector()
    result = None
    for i in range(10):
        temp = 40 if i % 2 == 0 else 52
        result = d.update(make_row(power=50, util=0, mem=100, temp=temp)) or result
    assert result is not None and result["type"] == "THERMAL_EMANATION", \
        "FAIL: ThermalEmanationDetector did not fire on known thermal gradient"
    print(f"[PASS] ThermalEmanationDetector fired correctly: {result['message']}")


def test_cross_tenant_bleeding_detector():
    """
    Real trigger: 100 idle samples (util==0, mem<200) establish baseline_w,
    then a further sample with power > baseline_w + bleed_threshold(20W).
    """
    d = CrossTenantBleedingDetector()
    for _ in range(100):
        d.update(make_row(power=50, util=0, mem=100))
    result = d.update(make_row(power=90, util=0, mem=100))
    assert result is not None and result["type"] == "CROSS_TENANT_BLEEDING", \
        "FAIL: CrossTenantBleedingDetector did not fire on known bleed pattern"
    print(f"[PASS] CrossTenantBleedingDetector fired correctly: {result['message']}")


def test_timing_covert_channel_detector():
    """
    Real trigger: window=100 samples where power direction reverses on
    nearly every step (regularity > 0.85).
    """
    d = TimingCovertChannelDetector()
    result = None
    for i in range(100):
        power = 50 if i % 2 == 0 else 65
        result = d.update(make_row(power=power, util=50, mem=1000)) or result
    assert result is not None and result["type"] == "TIMING_COVERT_CHANNEL", \
        "FAIL: TimingCovertChannelDetector did not fire on known regular pattern"
    print(f"[PASS] TimingCovertChannelDetector fired correctly: {result['message']}")


def test_cross_workload_clustering_detector():
    """
    Real trigger: add_alert() called for >= min_gpus(2) distinct GPUs
    within correlation_window(300s) fires CROSS_WORKLOAD_CLUSTER.
    """
    d = CrossWorkloadClusteringDetector()
    d.add_alert({"type": "GHOST_POWER", "gpu": 0})
    result = d.add_alert({"type": "GHOST_POWER", "gpu": 1})
    assert result is not None and result["type"] == "CROSS_WORKLOAD_CLUSTER", \
        "FAIL: CrossWorkloadClusteringDetector did not fire on known pattern"
    print(f"[PASS] CrossWorkloadClusteringDetector fired correctly: {result['message']}")


# --- Negative controls: confirm detectors stay silent on genuinely clean data ---

def test_ghost_power_silent_on_true_idle():
    d = GhostPowerDetector()
    result = None
    for _ in range(35):
        result = d.update(make_row(power=50, util=0, mem=100)) or result
    assert result is None, "FAIL: GhostPowerDetector fired on genuinely steady idle power"
    print("[PASS] GhostPowerDetector correctly silent on true idle")


def test_vram_residual_silent_on_clean_exit():
    d = VRAMResidualDetector()
    d.update(make_row(power=200, util=80, mem=8000))
    result = d.update(make_row(power=50, util=0, mem=50))
    assert result is None, "FAIL: VRAMResidualDetector fired on a genuinely clean memory exit"
    print("[PASS] VRAMResidualDetector correctly silent on clean exit")


if __name__ == "__main__":
    print("=== Positive Control Tests: detection/engines.py (7 detectors) ===\n")
    tests = [
        test_ghost_power_detector,
        test_vram_residual_detector,
        test_power_side_channel_detector,
        test_thermal_emanation_detector,
        test_cross_tenant_bleeding_detector,
        test_timing_covert_channel_detector,
        test_cross_workload_clustering_detector,
        test_ghost_power_silent_on_true_idle,
        test_vram_residual_silent_on_clean_exit,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {t.__name__}: {e}")
            failed += 1

    print(f"\n=== SUMMARY: {passed}/{len(tests)} passed, {failed} failed ===")
    if failed:
        sys.exit(1)
