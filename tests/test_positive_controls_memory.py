#!/usr/bin/env python3
# Watchdog AIDR
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer / Watchdog
#
# Positive Control Tests: detection/memory_attacks.py (3 detectors)
# =====================================================================
# WHY THIS EXISTS
#   Same rationale as the engines.py and hardware_attacks.py positive
#   control files. Includes SequentialVRAMReadDetector, CVSS 9.0
#   CRITICAL, described in the README as detecting "bulk VRAM scraping."
#
# HONEST STATUS
#   Verified locally (5/5 passing) before on-device confirmation.

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
from memory_attacks import (
    CacheSideChannelDetector,
    MIGPartitionDesyncDetector,
    SequentialVRAMReadDetector,
)


def make_row(util=0, util_mem=0, mem=0, mem_total=10000, index=0):
    return {
        "utilization.gpu": util,
        "utilization.memory": util_mem,
        "memory.used": mem,
        "memory.total": mem_total,
        "iso_timestamp": "2026-01-01T00:00:00Z",
        "index": index,
    }


def test_cache_side_channel_detector():
    """Real trigger: window=200, >40% of samples show util_mem>50 while
    avg GPU util stays <15%."""
    d = CacheSideChannelDetector()
    result = None
    for _ in range(90):
        result = d.update(make_row(util=5, util_mem=60)) or result
    for _ in range(110):
        result = d.update(make_row(util=5, util_mem=10)) or result
    assert result is not None and result["type"] == "CACHE_SIDE_CHANNEL", \
        "FAIL: CacheSideChannelDetector did not fire on known pattern"
    print(f"[PASS] CacheSideChannelDetector fired correctly: {result['message']}")


def test_mig_partition_desync_detector():
    """Real trigger: util_gpu==0 while util_mem>40 -- a single-sample check."""
    d = MIGPartitionDesyncDetector()
    result = d.update(make_row(util=0, util_mem=55))
    assert result is not None and result["type"] == "MIG_PARTITION_DESYNC", \
        "FAIL: MIGPartitionDesyncDetector did not fire on known desync pattern"
    print(f"[PASS] MIGPartitionDesyncDetector fired correctly: {result['message']}")


def test_sequential_vram_read_detector():
    """Real trigger (CVSS 9.0 CRITICAL): baseline set from 20 active-load
    samples, then 10 samples with high mem bandwidth util, near-zero GPU
    compute util, and coverage >= threshold fires SEQUENTIAL_VRAM_READ."""
    d = SequentialVRAMReadDetector()
    for _ in range(20):
        d.update(make_row(util=50, mem=1000))
    result = None
    for _ in range(10):
        result = d.update(make_row(util=0, util_mem=80, mem=2000, mem_total=10000)) or result
    assert result is not None and result["type"] == "SEQUENTIAL_VRAM_READ", \
        "FAIL: SequentialVRAMReadDetector did not fire on known bulk-read pattern"
    print(f"[PASS] SequentialVRAMReadDetector fired correctly (CVSS 9.0 CRITICAL): {result['message']}")


def test_mig_partition_silent_on_normal_load():
    d = MIGPartitionDesyncDetector()
    result = d.update(make_row(util=50, util_mem=50))
    assert result is None, "FAIL: MIGPartitionDesyncDetector fired on normal active load"
    print("[PASS] MIGPartitionDesyncDetector correctly silent on normal load")


def test_sequential_vram_read_silent_on_normal_inference():
    d = SequentialVRAMReadDetector()
    for _ in range(20):
        d.update(make_row(util=50, mem=1000))
    result = None
    for _ in range(10):
        result = d.update(make_row(util=60, util_mem=40, mem=1000, mem_total=10000)) or result
    assert result is None, "FAIL: SequentialVRAMReadDetector fired on genuinely normal inference"
    print("[PASS] SequentialVRAMReadDetector correctly silent on normal inference")


if __name__ == "__main__":
    print("=== Positive Control Tests: detection/memory_attacks.py (3 detectors) ===\n")
    tests = [
        test_cache_side_channel_detector,
        test_mig_partition_desync_detector,
        test_sequential_vram_read_detector,
        test_mig_partition_silent_on_normal_load,
        test_sequential_vram_read_silent_on_normal_inference,
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
