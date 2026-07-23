# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
tests/test_remediation_fixes.py

Tests for the fix to remediation/response.py:
  1. VRAM_RESIDUAL now maps to gpu_memory_reset (human-gated), not the old
     clear_vram which called torch.cuda.empty_cache() in Watchdog's own
     process and claimed success regardless of whether it did anything.
  2. _kill_gpu_processes now refuses to act when the alert doesn't name a
     specific PID, instead of killing every process on the GPU.

Run: python tests/test_remediation_fixes.py
"""

import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from remediation.response import RemediationEngine

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def fake_proc(stdout="", returncode=0):
    class R:
        pass
    r = R()
    r.stdout, r.returncode = stdout, returncode
    return r


def test_kill_process_refuses_without_target_pid():
    """The exact bug: DMA_ATTACK alerts don't name a PID. Confirm the
    engine refuses rather than killing every process on the GPU."""
    eng = RemediationEngine(auto_remediate=True, require_human=True)
    alert = {'type': 'DMA_ATTACK', 'gpu': 0}

    kill_calls = []
    def fake_run(cmd, **kw):
        if cmd[0] == 'kill':
            kill_calls.append(cmd)
            return fake_proc()
        return fake_proc(stdout="1111\n2222\n3333\n")

    with patch('subprocess.run', side_effect=fake_run):
        eng.handle(alert)

    check("kill_process: 'kill' subprocess is NEVER called when no "
          "target PID is in the alert -- no innocent process touched",
          len(kill_calls) == 0, f"kill was called with: {kill_calls}")


def test_kill_process_targets_only_named_pid():
    """If a future alert DOES name a specific PID, confirm ONLY that one
    gets killed, not the others present on the GPU."""
    eng = RemediationEngine(auto_remediate=True, require_human=True)
    alert = {'type': 'DMA_ATTACK', 'gpu': 0, 'pid': 2222}

    kill_calls = []
    def fake_run(cmd, **kw):
        if cmd[0] == 'kill':
            kill_calls.append(cmd)
            return fake_proc()
        return fake_proc(stdout="1111\n2222\n3333\n")

    with patch('subprocess.run', side_effect=fake_run):
        eng.handle(alert)

    check("kill_process: kills exactly one process when a target PID is named",
          len(kill_calls) == 1, f"got {kill_calls}")
    check("kill_process: kills the CORRECT targeted PID, not a different one",
          kill_calls and kill_calls[0][2] == '2222', f"got {kill_calls}")


def test_kill_process_target_pid_not_present_is_reported_not_silently_ignored():
    eng = RemediationEngine(auto_remediate=True, require_human=True)
    alert = {'type': 'DMA_ATTACK', 'gpu': 0, 'pid': 9999}

    def fake_run(cmd, **kw):
        if cmd[0] == 'kill':
            return fake_proc()
        return fake_proc(stdout="1111\n2222\n")

    log_entries = []
    with patch('subprocess.run', side_effect=fake_run), \
         patch('remediation.response.log_action',
               side_effect=lambda a, r, al: log_entries.append((a, r))):
        eng.handle(alert)

    check("kill_process: target PID absent from GPU is reported clearly, "
          "not silently swallowed",
          any('NOT_FOUND' in r for a, r in log_entries), f"got {log_entries}")


def test_vram_residual_maps_to_gpu_memory_reset_not_clear_vram():
    check("VRAM_RESIDUAL action list no longer contains the old "
          "'clear_vram' name",
          'clear_vram' not in RemediationEngine.TYPE_ACTIONS['VRAM_RESIDUAL'])
    check("VRAM_RESIDUAL maps to gpu_memory_reset",
          'gpu_memory_reset' in RemediationEngine.TYPE_ACTIONS['VRAM_RESIDUAL'])


def test_gpu_memory_reset_is_human_gated_by_default():
    """The most important behavioral check: by default (require_human=True,
    the class default), a VRAM_RESIDUAL alert must NOT actually attempt
    any GPU action -- it should be skipped and logged as such."""
    eng = RemediationEngine(auto_remediate=True)
    alert = {'type': 'VRAM_RESIDUAL', 'gpu': 0}

    log_entries = []
    with patch('subprocess.run') as mock_run, \
         patch('remediation.response.log_action',
               side_effect=lambda a, r, al: log_entries.append((a, r))):
        eng.handle(alert)

    check("gpu_memory_reset: skipped by default (human approval required), "
          "not silently executed",
          any(r == 'SKIPPED_HUMAN_REQUIRED' for a, r in log_entries
              if a == 'gpu_memory_reset'),
          f"got {log_entries}")
    check("gpu_memory_reset: no subprocess call made when gated off",
          not mock_run.called, f"subprocess.run was called: {mock_run.call_args_list}")


def test_gpu_memory_reset_gives_honest_message_when_explicitly_enabled():
    """If an operator explicitly opts out of the human gate, the engine
    must not claim false success -- it should say plainly that this
    cannot be done automatically."""
    eng = RemediationEngine(auto_remediate=True, require_human=False)
    alert = {'type': 'VRAM_RESIDUAL', 'gpu': 0}

    log_entries = []
    with patch('remediation.response.log_action',
               side_effect=lambda a, r, al: log_entries.append((a, r))):
        eng.handle(alert)

    reset_results = [r for a, r in log_entries if a == 'gpu_memory_reset']
    check("gpu_memory_reset: does not claim 'VRAM_CLEARED' or any false "
          "success when actually invoked",
          reset_results and 'CLEARED' not in reset_results[0],
          f"got {reset_results}")
    check("gpu_memory_reset: message explains WHY this can't be done "
          "automatically, not just a bare status code",
          reset_results and 'REQUIRES_HUMAN_APPROVAL' in reset_results[0],
          f"got {reset_results}")


def test_default_auto_remediate_off_still_skips_everything_but_log():
    eng = RemediationEngine()
    alert = {'type': 'DMA_ATTACK', 'gpu': 0}

    with patch('subprocess.run') as mock_run:
        eng.handle(alert)

    check("REGRESSION: default engine (auto_remediate=False) still makes "
          "no subprocess calls at all for a kill_process alert",
          not mock_run.called)


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
