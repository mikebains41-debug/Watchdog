#!/usr/bin/env python3
# Watchdog AIDR
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer / Watchdog
#
# Positive Control Tests: detection/hardware_attacks.py (4 detectors)
# =======================================================================
# WHY THIS EXISTS
#   Same rationale as test_positive_controls_engines.py: proves each
#   detector can fire on its real, intended trigger pattern before
#   trusting any "0 alerts" result. Includes DMAAttackDetector, the
#   highest-severity engine in the catalog (CVSS 9.6 CRITICAL).
#
# HONEST STATUS
#   Verified locally (6/6 passing) before on-device confirmation.

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
from hardware_attacks import (
    ClockGlitchDetector,
    VoltageGlitchDetector,
    DMAAttackDetector,
    LaserInjectionDetector,
)


def make_row(power=0, util=0, mem=0, temp=40, sm_clock=1000, util_mem=0, index=0):
    return {
        "power.draw": power,
        "utilization.gpu": util,
        "memory.used": mem,
        "temperature.gpu": temp,
        "clocks.sm": sm_clock,
        "utilization.memory": util_mem,
        "iso_timestamp": "2026-01-01T00:00:00Z",
        "index": index,
    }


def test_clock_glitch_detector():
    """Real trigger: last-10-sample window, SM clock drop >=10% while util>10."""
    d = ClockGlitchDetector()
    result = None
    for i in range(9):
        result = d.update(make_row(sm_clock=1000, util=50)) or result
    result = d.update(make_row(sm_clock=850, util=50)) or result
    assert result is not None and result["type"] == "CLOCK_GLITCH", \
        "FAIL: ClockGlitchDetector did not fire on known clock drop"
    print(f"[PASS] ClockGlitchDetector fired correctly: {result['message']}")


def test_voltage_glitch_detector():
    """Real trigger: 100-sample window, power droop >50W in last 20 samples
    while utilization stays stable and >10%."""
    d = VoltageGlitchDetector()
    result = None
    for _ in range(80):
        result = d.update(make_row(power=150, util=50)) or result
    for _ in range(15):
        result = d.update(make_row(power=200, util=50)) or result
    for _ in range(5):
        result = d.update(make_row(power=100, util=50)) or result
    assert result is not None and result["type"] == "VOLTAGE_GLITCH", \
        "FAIL: VoltageGlitchDetector did not fire on known power droop"
    print(f"[PASS] VoltageGlitchDetector fired correctly: {result['message']}")


def test_dma_attack_detector():
    """Real trigger (CVSS 9.6 CRITICAL): after baseline established (50
    idle samples), a sample with util==0, util_mem>30, and mem well above
    baseline fires DMA_ATTACK."""
    d = DMAAttackDetector()
    for _ in range(50):
        d.update(make_row(util=0, mem=1000))
    d.update(make_row(util=0, mem=1000))
    result = d.update(make_row(util=0, mem=1200, util_mem=50))
    assert result is not None and result["type"] == "DMA_ATTACK", \
        "FAIL: DMAAttackDetector did not fire on known DMA pattern"
    print(f"[PASS] DMAAttackDetector fired correctly (CVSS 9.6 CRITICAL): {result['message']}")


def test_laser_injection_detector():
    """Real trigger: temp delta >=5.0C within a 0.5s rolling window."""
    d = LaserInjectionDetector()
    result = None
    for _ in range(4):
        result = d.update(make_row(temp=40)) or result
    result = d.update(make_row(temp=52)) or result
    assert result is not None and result["type"] == "LASER_INJECTION", \
        "FAIL: LaserInjectionDetector did not fire on known thermal spike"
    print(f"[PASS] LaserInjectionDetector fired correctly: {result['message']}")


def test_clock_glitch_silent_on_stable_clocks():
    d = ClockGlitchDetector()
    result = None
    for _ in range(15):
        result = d.update(make_row(sm_clock=1000, util=50)) or result
    assert result is None, "FAIL: ClockGlitchDetector fired on genuinely stable clocks"
    print("[PASS] ClockGlitchDetector correctly silent on stable clocks")


def test_dma_attack_silent_on_normal_baseline():
    d = DMAAttackDetector()
    for _ in range(50):
        d.update(make_row(util=0, mem=1000))
    d.update(make_row(util=0, mem=1000))
    result = d.update(make_row(util=0, mem=1010, util_mem=5))
    assert result is None, "FAIL: DMAAttackDetector fired on genuinely normal memory state"
    print("[PASS] DMAAttackDetector correctly silent on normal baseline")


if __name__ == "__main__":
    print("=== Positive Control Tests: detection/hardware_attacks.py (4 detectors) ===\n")
    tests = [
        test_clock_glitch_detector,
        test_voltage_glitch_detector,
        test_dma_attack_detector,
        test_laser_injection_detector,
        test_clock_glitch_silent_on_stable_clocks,
        test_dma_attack_silent_on_normal_baseline,
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
