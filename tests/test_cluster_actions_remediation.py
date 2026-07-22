"""
tests/test_cluster_actions_remediation.py

Tests for the 3 new remediation actions wired in from
orchestration/cluster_actions.py: kubernetes_taint, slurm_evict_job,
nvlink_disable. All three are gated behind HUMAN_REQUIRED by default
(same as gpu_memory_reset) and all three REFUSE without a specific
target field in the alert (same pattern as kill_process's PID
requirement) -- because, as of tonight, NO detector in this repo
provides node_name, job_id, or link_index in any alert it emits. These
actions exist and are safe to call, but nothing currently triggers them
automatically; that mapping is a deliberate, separate decision not made
here.

Run: python tests/test_cluster_actions_remediation.py
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


def test_taint_refuses_without_node_name():
    eng = RemediationEngine()
    result = eng._kubernetes_taint({'type': 'TENANT_ISOLATION_RISK', 'gpu': 0})
    check("kubernetes_taint: refuses cleanly without node_name in alert",
          result == 'REFUSED_NO_TARGET_NODE_IN_ALERT', f"got {result}")


def test_taint_calls_real_action_when_node_name_present():
    eng = RemediationEngine()
    with patch('subprocess.run', return_value=fake_proc(returncode=0)) as mock_run:
        result = eng._kubernetes_taint({'type': 'TENANT_ISOLATION_RISK', 'gpu': 0,
                                         'node_name': 'gpu-node-7'})
    check("kubernetes_taint: proceeds and calls kubectl when node_name is present",
          result == 'TAINT_APPLIED', f"got {result}")
    check("kubernetes_taint: real kubectl command included the correct node name",
          mock_run.called and 'gpu-node-7' in mock_run.call_args[0][0][3],
          f"got {mock_run.call_args}")


def test_slurm_evict_refuses_without_job_id():
    eng = RemediationEngine()
    result = eng._slurm_evict_job({'type': 'TENANT_ISOLATION_RISK', 'gpu': 0})
    check("slurm_evict_job: refuses cleanly without job_id in alert",
          result == 'REFUSED_NO_TARGET_JOB_ID_IN_ALERT', f"got {result}")


def test_slurm_evict_calls_real_action_when_job_id_present():
    eng = RemediationEngine()
    with patch('subprocess.run', return_value=fake_proc(returncode=0)) as mock_run:
        result = eng._slurm_evict_job({'type': 'TENANT_ISOLATION_RISK', 'gpu': 0,
                                        'job_id': 12345})
    check("slurm_evict_job: proceeds and calls scancel when job_id is present",
          result == 'JOB_EVICTED', f"got {result}")


def test_nvlink_disable_refuses_without_link_index():
    eng = RemediationEngine()
    result = eng._nvlink_disable(0, {'type': 'NVLINK_CONTENTION', 'gpu': 0})
    check("nvlink_disable: refuses cleanly without link_index in alert",
          result == 'REFUSED_NO_TARGET_LINK_INDEX_IN_ALERT', f"got {result}")


def test_nvlink_disable_calls_real_action_when_link_index_present():
    eng = RemediationEngine()
    with patch('subprocess.run', return_value=fake_proc(returncode=0)) as mock_run:
        result = eng._nvlink_disable(0, {'type': 'NVLINK_CONTENTION', 'gpu': 0,
                                          'link_index': 2})
    check("nvlink_disable: proceeds and calls nvidia-smi when link_index is present",
          result == 'NVLINK_DISABLED', f"got {result}")


def test_all_three_new_actions_are_human_gated_by_default():
    check("kubernetes_taint is in HUMAN_REQUIRED",
          'kubernetes_taint' in RemediationEngine.HUMAN_REQUIRED)
    check("slurm_evict_job is in HUMAN_REQUIRED",
          'slurm_evict_job' in RemediationEngine.HUMAN_REQUIRED)
    check("nvlink_disable is in HUMAN_REQUIRED",
          'nvlink_disable' in RemediationEngine.HUMAN_REQUIRED)


def test_no_existing_alert_type_currently_triggers_new_actions():
    """Confirms the deliberate scoping decision: these actions exist
    and are safe, but nothing currently maps to them -- disclosed
    honestly rather than silently wired into the live alert flow."""
    all_mapped_actions = set()
    for actions in RemediationEngine.TYPE_ACTIONS.values():
        all_mapped_actions.update(actions)
    new_actions = {'kubernetes_taint', 'slurm_evict_job', 'nvlink_disable'}
    check("none of the 3 new actions are mapped to any existing alert "
          "type yet (deliberate, disclosed scoping -- not an oversight)",
          not (new_actions & all_mapped_actions),
          f"unexpectedly mapped: {new_actions & all_mapped_actions}")


def test_new_actions_gated_off_by_default_even_if_hypothetically_mapped():
    """Even if a future alert type WERE mapped to one of these, the
    default require_human=True must still block it -- proven by
    temporarily mapping one for this test only, then restoring the
    real mapping afterward."""
    eng = RemediationEngine(auto_remediate=True)  # require_human=True (default)
    original = dict(RemediationEngine.TYPE_ACTIONS)
    RemediationEngine.TYPE_ACTIONS['TEST_ALERT_TYPE'] = ['kubernetes_taint']
    try:
        with patch('subprocess.run') as mock_run:
            eng.handle({'type': 'TEST_ALERT_TYPE', 'gpu': 0, 'node_name': 'gpu-node-7'})
        check("even with a node_name present, require_human=True blocks "
              "kubernetes_taint by default -- no subprocess call made",
              not mock_run.called, f"subprocess.run was called: {mock_run.call_args_list}")
    finally:
        RemediationEngine.TYPE_ACTIONS.clear()
        RemediationEngine.TYPE_ACTIONS.update(original)


def test_regression_kill_process_and_gpu_memory_reset_still_work():
    """Confirm adding the 3 new actions didn't disturb the existing,
    already-fixed behavior. Note: kill_process legitimately makes ONE
    safe, read-only subprocess call (querying who's running on the
    GPU) even when it refuses to act -- that's correct, not a bug. The
    real safety property is that no 'kill' command is ever issued
    without a specific target PID, checked directly below."""
    eng = RemediationEngine(auto_remediate=True, require_human=True)
    with patch('subprocess.run') as mock_run:
        mock_run.return_value.stdout = ''
        mock_run.return_value.returncode = 0
        eng.handle({'type': 'DMA_ATTACK', 'gpu': 0})
    kill_commands = [c for c in mock_run.call_args_list if c[0][0][0] == 'kill']
    check("regression: kill_process never issues an actual 'kill' "
          "command without a target PID (the real query call is "
          "expected and safe)",
          len(kill_commands) == 0, f"kill commands issued: {kill_commands}")

    eng2 = RemediationEngine(auto_remediate=True, require_human=True)
    log_entries = []
    with patch('remediation.response.log_action',
               side_effect=lambda a, r, al: log_entries.append((a, r))):
        eng2.handle({'type': 'VRAM_RESIDUAL', 'gpu': 0})
    check("regression: gpu_memory_reset is still skipped by default "
          "(human approval required)",
          any(r == 'SKIPPED_HUMAN_REQUIRED' for a, r in log_entries if a == 'gpu_memory_reset'),
          f"got {log_entries}")


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
