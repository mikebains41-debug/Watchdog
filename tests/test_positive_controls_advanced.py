#!/usr/bin/env python3
# Watchdog AIDR
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer / Watchdog
#
# Positive Control Tests: detection/advanced.py (5 detectors)
# ================================================================
# WHY THIS EXISTS
#   Same rationale as the four prior positive control files. This is
#   the final module -- completes positive-control coverage for all
#   24 detection engines in the Watchdog catalog.
#
# HONEST LIMITATION -- READ THIS
#   Two of the five detectors in this module cannot be given a true
#   synthetic positive control, because their logic depends on real
#   hardware tools rather than telemetry values passed in:
#     - ModelMutationDetector.compute_vram_checksum() calls
#       torch.cuda.is_available() and allocates real VRAM directly.
#       It cannot be triggered with synthetic input; it requires an
#       actual GPU with CUDA available.
#     - NVLinkFabricDetector.sample() shells out to the real
#       `nvidia-smi nvlink --status` command. This test mocks that
#       subprocess call to prove the detector's PARSING LOGIC is
#       correct, but this is not the same as confirming it against
#       real nvidia-smi output on real NVLink hardware.
#   Both are marked explicitly below rather than silently skipped or
#   faked with a synthetic input that doesn't reflect production.
#
# HONEST STATUS
#   The 3 testable detectors verified locally before on-device
#   confirmation. The mocked NVLinkFabricDetector test is a logic
#   check, not a hardware validation.

import sys
import os
import time
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
from advanced import (
    RowhammerProxyDetector,
    ModelMutationDetector,
    PerfCounterSideChannelDetector,
    NVLinkFabricDetector,
    SupplyChainDetector,
)


def make_row(power=0, util=0, mem=0, util_mem=0, name="", index=0):
    return {
        "power.draw": power,
        "utilization.gpu": util,
        "memory.used": mem,
        "utilization.memory": util_mem,
        "name": name,
        "iso_timestamp": "2026-01-01T00:00:00Z",
        "index": index,
    }


def test_rowhammer_proxy_detector():
    """Real trigger: window=50, >60% of samples show util<5 with mem>500,
    and memory variance across the window exceeds 100MB."""
    d = RowhammerProxyDetector()
    result = None
    for i in range(50):
        mem = 600 if i % 2 == 0 else 800
        result = d.update(make_row(util=2, mem=mem)) or result
    assert result is not None and result["type"] == "ROWHAMMER_PROXY", \
        "FAIL: RowhammerProxyDetector did not fire on known pattern"
    print(f"[PASS] RowhammerProxyDetector fired correctly: {result['message']}")


def test_perf_counter_side_channel_detector():
    """Real trigger: window=100, current util_gpu<5, memory utilization
    variance >20% across window, GPU utilization variance <5%."""
    d = PerfCounterSideChannelDetector()
    result = None
    for i in range(100):
        util_mem = 10 if i % 2 == 0 else 45
        result = d.update(make_row(util=2, util_mem=util_mem)) or result
    assert result is not None and result["type"] == "PERF_COUNTER_SIDE_CHANNEL", \
        "FAIL: PerfCounterSideChannelDetector did not fire on known pattern"
    print(f"[PASS] PerfCounterSideChannelDetector fired correctly: {result['message']}")


def test_supply_chain_detector():
    """Real trigger: active GPU (util>=1, power>=10) reporting power
    draw >15% above the expected max for its named architecture."""
    d = SupplyChainDetector()
    result = d.check_counterfeit(make_row(power=900, util=50, name="NVIDIA H200"))
    assert result is not None and result["type"] == "SUPPLY_CHAIN_ANOMALY", \
        "FAIL: SupplyChainDetector did not fire on known overpower pattern"
    print(f"[PASS] SupplyChainDetector fired correctly: {result['message']}")


def test_nvlink_fabric_detector_mocked():
    """
    HONEST LIMITATION: this detector's real data source is the
    `nvidia-smi nvlink --status` shell command, not telemetry passed in.
    This test mocks that subprocess call to confirm the PARSING LOGIC
    correctly identifies 'inactive'/'error' status text -- it does NOT
    confirm behavior against real nvidia-smi output on real hardware.
    """
    d = NVLinkFabricDetector()
    with patch("advanced.subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = "Link 0: inactive\nLink 1: active"
        mock_run.return_value = mock_result
        result = d.update(make_row())
    assert result is not None and result["type"] == "NVLINK_ANOMALY", \
        "FAIL: NVLinkFabricDetector did not fire on known inactive-link pattern (mocked)"
    print(f"[PASS] NVLinkFabricDetector fired correctly on MOCKED input: {result['message']}")
    print("       (parsing logic only -- not validated against real nvidia-smi/hardware)")


def test_model_mutation_detector_honest_limitation():
    """
    HONEST LIMITATION: ModelMutationDetector.compute_vram_checksum()
    calls torch.cuda.is_available() and allocates real VRAM directly.
    It cannot be given a meaningful synthetic positive control. This
    test confirms it degrades safely (returns None) without CUDA --
    correct safe behavior, NOT proof it catches real model mutation.
    """
    d = ModelMutationDetector()
    result = d.check(gpu_index=0)
    assert result is None, (
        "Unexpected: got a result without CUDA hardware -- verify this "
        "environment doesn't have an unexpected torch/CUDA setup"
    )
    print("[INFO] ModelMutationDetector requires real CUDA hardware to")
    print("       meaningfully test -- confirmed safe no-op without it.")
    print("       NOT yet validated as a working detector on real hardware.")


def test_rowhammer_proxy_silent_on_normal_active_use():
    d = RowhammerProxyDetector()
    result = None
    for _ in range(50):
        result = d.update(make_row(util=60, mem=8000)) or result
    assert result is None, "FAIL: RowhammerProxyDetector fired on normal active GPU use"
    print("[PASS] RowhammerProxyDetector correctly silent on normal active use")


def test_supply_chain_silent_on_normal_power():
    d = SupplyChainDetector()
    result = d.check_counterfeit(make_row(power=650, util=50, name="NVIDIA H200"))
    assert result is None, "FAIL: SupplyChainDetector fired on normal in-spec power draw"
    print("[PASS] SupplyChainDetector correctly silent on normal power draw")


if __name__ == "__main__":
    print("=== Positive Control Tests: detection/advanced.py (5 detectors) ===\n")
    tests = [
        test_rowhammer_proxy_detector,
        test_perf_counter_side_channel_detector,
        test_supply_chain_detector,
        test_nvlink_fabric_detector_mocked,
        test_model_mutation_detector_honest_limitation,
        test_rowhammer_proxy_silent_on_normal_active_use,
        test_supply_chain_silent_on_normal_power,
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
    print("\nNOTE: ModelMutationDetector and NVLinkFabricDetector require")
    print("real CUDA/NVLink hardware for genuine validation -- see the")
    print("HONEST LIMITATION docstrings above for what was and wasn't proven.")
    if failed:
        sys.exit(1)
