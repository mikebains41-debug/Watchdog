#!/usr/bin/env python3
# Watchdog AIDR
# Author: Manmohan (Mike) Bains
# Project: GPU Optimizer / Watchdog
#
# Positive Control Tests: detection/llm_attacks.py (5 detectors)
# ===================================================================
# WHY THIS EXISTS
#   Same rationale as prior positive control files. Includes
#   AgentSessionVRAMRetentionDetector, which directly applies CVE-2048350
#   to agentic AI / drug-discovery threat models (CVSS 8.4).
#
# HONEST STATUS
#   Verified locally (7/7 passing) before on-device confirmation.
#   Constructor params (calibration_samples, baseline_samples) are
#   reduced from README defaults purely to keep test runtime short --
#   the underlying trigger LOGIC is identical to production defaults.

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
from llm_attacks import (
    InferencePowerFingerprintDetector,
    AgentOrchestrationAnomalyDetector,
    PromptInjectionSideEffectDetector,
    AgentSessionVRAMRetentionDetector,
    InterAgentHandoffAnomalyDetector,
)


def make_row(power=0, util=0, mem=0, index=0):
    return {
        "power.draw": power,
        "utilization.gpu": util,
        "memory.used": mem,
        "iso_timestamp": "2026-01-01T00:00:00Z",
        "index": index,
    }


def test_inference_power_fingerprint_detector():
    """Real trigger: calibrated baseline mean/std from active-load samples,
    then a sustained deviation z-score > deviation_threshold*10."""
    d = InferencePowerFingerprintDetector(calibration_samples=20)
    for i in range(20):
        d.update(make_row(power=190 if i % 2 == 0 else 210, util=50))
    d.update(make_row(power=200, util=50))
    result = None
    for _ in range(20):
        result = d.update(make_row(power=400, util=50)) or result
    assert result is not None and result["type"] == "INFERENCE_POWER_ANOMALY", \
        "FAIL: InferencePowerFingerprintDetector did not fire on known deviation"
    print(f"[PASS] InferencePowerFingerprintDetector fired correctly: {result['message']}")


def test_agent_orchestration_anomaly_detector():
    """Real trigger: window=60, >50% of samples show power>threshold(100W)
    while util<10 -- agent claims idle but GPU is busy."""
    d = AgentOrchestrationAnomalyDetector()
    result = None
    for _ in range(60):
        result = d.update(make_row(power=150, util=5)) or result
    assert result is not None and result["type"] == "AGENT_ORCHESTRATION_ANOMALY", \
        "FAIL: AgentOrchestrationAnomalyDetector did not fire on known pattern"
    print(f"[PASS] AgentOrchestrationAnomalyDetector fired correctly: {result['message']}")


def test_prompt_injection_side_effect_detector():
    """Real trigger: window=20, a power spike above the running mean
    exceeding spike_threshold(30W) while util>20."""
    d = PromptInjectionSideEffectDetector()
    result = None
    for _ in range(19):
        result = d.update(make_row(power=100, util=50)) or result
    result = d.update(make_row(power=200, util=50)) or result
    assert result is not None and result["type"] == "PROMPT_INJECTION_SIDEEFFECT", \
        "FAIL: PromptInjectionSideEffectDetector did not fire on known spike"
    print(f"[PASS] PromptInjectionSideEffectDetector fired correctly: {result['message']}")


def test_agent_session_vram_retention_detector():
    """Real trigger (applies CVE-2048350 to agentic AI): active session
    (util>10) followed by sustained idle (util==0) with memory still
    above threshold fires AGENT_VRAM_RETENTION."""
    d = AgentSessionVRAMRetentionDetector()
    d.update(make_row(power=200, util=50, mem=5000))
    result = None
    for _ in range(35):
        result = d.update(make_row(power=50, util=0, mem=500)) or result
    assert result is not None and result["type"] == "AGENT_VRAM_RETENTION", \
        "FAIL: AgentSessionVRAMRetentionDetector did not fire on known retention pattern"
    print(f"[PASS] AgentSessionVRAMRetentionDetector fired correctly (CVSS 8.4): {result['message']}")


def test_inter_agent_handoff_anomaly_detector():
    """Real trigger: agent goes idle (establishing a handoff baseline
    power), then resumes at a power level well above that baseline --
    consistent with a compromised upstream agent's payload."""
    d = InterAgentHandoffAnomalyDetector(baseline_samples=1)
    d.update(make_row(power=100, util=50))
    d.update(make_row(power=80, util=0))
    result = None
    for _ in range(10):
        result = d.update(make_row(power=200, util=60)) or result
    assert result is not None and result["type"] == "INTER_AGENT_HANDOFF_ANOMALY", \
        "FAIL: InterAgentHandoffAnomalyDetector did not fire on known anomalous resume"
    print(f"[PASS] InterAgentHandoffAnomalyDetector fired correctly: {result['message']}")


def test_agent_orchestration_silent_on_true_idle():
    d = AgentOrchestrationAnomalyDetector()
    result = None
    for _ in range(60):
        result = d.update(make_row(power=20, util=0)) or result
    assert result is None, "FAIL: AgentOrchestrationAnomalyDetector fired on genuine idle"
    print("[PASS] AgentOrchestrationAnomalyDetector correctly silent on true idle")


def test_agent_session_vram_silent_on_clean_exit():
    d = AgentSessionVRAMRetentionDetector()
    d.update(make_row(power=200, util=50, mem=5000))
    result = None
    for _ in range(35):
        result = d.update(make_row(power=50, util=0, mem=10)) or result
    assert result is None, "FAIL: AgentSessionVRAMRetentionDetector fired on genuinely clean exit"
    print("[PASS] AgentSessionVRAMRetentionDetector correctly silent on clean exit")


if __name__ == "__main__":
    print("=== Positive Control Tests: detection/llm_attacks.py (5 detectors) ===\n")
    tests = [
        test_inference_power_fingerprint_detector,
        test_agent_orchestration_anomaly_detector,
        test_prompt_injection_side_effect_detector,
        test_agent_session_vram_retention_detector,
        test_inter_agent_handoff_anomaly_detector,
        test_agent_orchestration_silent_on_true_idle,
        test_agent_session_vram_silent_on_clean_exit,
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
