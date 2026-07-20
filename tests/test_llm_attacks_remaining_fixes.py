"""
tests/test_llm_attacks_remaining_fixes.py

Tests for the 2 remaining fixed detectors in llm_attacks.py:
PromptInjectionSideEffectDetector, AgentSessionVRAMRetentionDetector.
Does NOT re-test InferencePowerFingerprintDetector, 
AgentOrchestrationAnomalyDetector, or InterAgentHandoffAnomalyDetector --
already covered by tests/test_llm_attacks_fixes.py.

Run: python tests/test_llm_attacks_remaining_fixes.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.llm_attacks import (
    PromptInjectionSideEffectDetector,
    AgentSessionVRAMRetentionDetector,
    AgentSessionVRAMUnavailable,
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


def row(**kw):
    base = {'index': 0, 'iso_timestamp': '2026-07-19T00:00:00'}
    base.update(kw)
    return base


def test_prompt_injection_negative_normal_prompt_variance():
    """The exact bug: comparing window's own max to its own mean. Normal
    variance from different prompt lengths must not fire."""
    d = PromptInjectionSideEffectDetector(calibration_samples=30,
                                           require_consecutive=3)
    for i in range(31):
        d.update(row(**{'power.draw': 300 + (i % 5) - 2, 'utilization.gpu': 50}))
    alerts = []
    for i in range(20):
        alerts.append(d.update(row(**{'power.draw': 300 + (i % 5) - 2,
                                       'utilization.gpu': 50})))
    fired = [a for a in alerts if a]
    check("PROMPT_INJECTION NEGATIVE: silent on normal small power variance",
          len(fired) == 0, f"fired {len(fired)} times -- FALSE POSITIVE")


def test_prompt_injection_positive_sustained_spike():
    d = PromptInjectionSideEffectDetector(calibration_samples=30,
                                           require_consecutive=3)
    for i in range(31):
        d.update(row(**{'power.draw': 300 + (i % 3) - 1, 'utilization.gpu': 50}))
    alerts = [d.update(row(**{'power.draw': 400, 'utilization.gpu': 50}))
              for _ in range(5)]
    fired = [a for a in alerts if a]
    check("PROMPT_INJECTION POSITIVE: fires on sustained large power spike",
          len(fired) >= 1 and fired[0]['type'] == 'PROMPT_INJECTION_SIDEEFFECT',
          f"got {len(fired)} fired")


def test_prompt_injection_notes_overlap():
    d = PromptInjectionSideEffectDetector(calibration_samples=30,
                                           require_consecutive=3)
    for i in range(31):
        d.update(row(**{'power.draw': 300 + (i % 3) - 1, 'utilization.gpu': 50}))
    alerts = [d.update(row(**{'power.draw': 400, 'utilization.gpu': 50}))
              for _ in range(5)]
    fired = [a for a in alerts if a]
    check("PROMPT_INJECTION: notes overlap with InferencePowerFingerprintDetector",
          fired and 'InferencePowerFingerprintDetector' in fired[0]['message'],
          f"got {fired[0]['message'] if fired else 'none'}")


def test_agent_vram_strict_raises_without_compute_apps():
    """Same contract as VRAMResidualDetector: strict=True must raise, not
    silently degrade to the old aggregate-memory heuristic."""
    d = AgentSessionVRAMRetentionDetector(strict=True)
    try:
        d.update(row(**{'memory.used': 500, 'utilization.gpu': 0}))
        check("AGENT_VRAM strict=True raises when compute_apps is absent",
              False, "did not raise")
    except AgentSessionVRAMUnavailable:
        check("AGENT_VRAM strict=True raises when compute_apps is absent", True)


def test_agent_vram_negative_resident_model_idle_process_alive():
    """The exact bug: a model resident and idle between requests, with
    its process still ALIVE, is the most common state in production
    serving. Must NOT fire -- the process never exited."""
    d = AgentSessionVRAMRetentionDetector(retention_threshold_mb=100,
                                           grace_samples=2, strict=True)
    alerts = []
    for _ in range(10):
        alerts.append(d.update(row(**{
            'memory.used': 5000, 'utilization.gpu': 0,
            'compute_apps': [{'pid': 111, 'used_memory': 5000}],
        })))
    fired = [a for a in alerts if a]
    check("AGENT_VRAM NEGATIVE: silent when the owning process never "
          "exited (resident model, idle between requests -- the "
          "original bug's exact false-positive scenario)",
          len(fired) == 0, f"fired {len(fired)} times -- FALSE POSITIVE")


def test_agent_vram_positive_pid_exits_with_unclaimed_memory():
    """Real trigger: PID 111 was active, then disappears from
    compute_apps, but total memory.used doesn't drop to match -- that
    gap is the actual finding (CVE-2048350)."""
    d = AgentSessionVRAMRetentionDetector(retention_threshold_mb=100,
                                           grace_samples=2, strict=True)
    d.update(row(**{
        'memory.used': 5000, 'utilization.gpu': 20,
        'compute_apps': [{'pid': 111, 'used_memory': 5000}],
    }))
    alerts = []
    for _ in range(3):
        alerts.append(d.update(row(**{
            'memory.used': 5000, 'utilization.gpu': 0,
            'compute_apps': [],
        })))
    fired = [a for a in alerts if a]
    check("AGENT_VRAM POSITIVE: fires when a PID exits and its memory "
          "remains unclaimed",
          len(fired) >= 1 and fired[0]['type'] == 'AGENT_VRAM_RETENTION'
          and fired[0]['exited_pid'] == 111,
          f"got {fired}")


def test_agent_vram_negative_clean_exit_memory_actually_freed():
    """A PID exits and memory.used correctly drops with it -- clean exit,
    no retention, must not fire."""
    d = AgentSessionVRAMRetentionDetector(retention_threshold_mb=100,
                                           grace_samples=2, strict=True)
    d.update(row(**{
        'memory.used': 5000, 'utilization.gpu': 20,
        'compute_apps': [{'pid': 111, 'used_memory': 5000}],
    }))
    alerts = []
    for _ in range(3):
        alerts.append(d.update(row(**{
            'memory.used': 50, 'utilization.gpu': 0,
            'compute_apps': [],
        })))
    fired = [a for a in alerts if a]
    check("AGENT_VRAM NEGATIVE: silent on a genuinely clean exit where "
          "memory.used actually drops with the process",
          len(fired) == 0, f"fired {len(fired)} times -- FALSE POSITIVE")


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
