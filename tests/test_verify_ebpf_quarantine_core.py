import sys
import os
import platform
from unittest.mock import patch, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.verify_ebpf_quarantine_core import AdvancedEBPFVerifier

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def test_kernel_version_passes_above_minimum():
    v = AdvancedEBPFVerifier()
    with patch.object(platform, 'release', return_value='5.15.0-140-generic'):
        result = v.check_kernel_version()
    check("kernel_version: 5.15.0 passes (>= 5.4.0 minimum)", result is True)


def test_kernel_version_fails_below_minimum():
    v = AdvancedEBPFVerifier()
    with patch.object(platform, 'release', return_value='4.19.0-generic'):
        result = v.check_kernel_version()
    check("kernel_version: 4.19.0 fails (< 5.4.0 minimum)", result is False)


def test_kernel_version_handles_unparseable():
    v = AdvancedEBPFVerifier()
    with patch.object(platform, 'release', return_value='not-a-version'):
        result = v.check_kernel_version()
    check("kernel_version: unparseable string fails cleanly, no crash",
          result is False)


def test_cgroup2_pass_when_writable():
    v = AdvancedEBPFVerifier()
    mounts = "cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev 0 0\n"
    with patch('builtins.open', mock_open(read_data=mounts)), \
         patch('os.access', return_value=True):
        result = v.check_cgroup2_unified()
    check("cgroup2: PASS when mount is rw AND process has write access",
          result is True)


def test_cgroup2_fails_when_mounted_rw_but_no_process_access():
    v = AdvancedEBPFVerifier()
    mounts = "cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev 0 0\n"
    with patch('builtins.open', mock_open(read_data=mounts)), \
         patch('os.access', return_value=False):
        result = v.check_cgroup2_unified()
    check("cgroup2: FAILS when host mount is rw but THIS process can't "
          "write -- the case the original version silently passed",
          result is False)


def test_cgroup2_fails_when_mounted_readonly():
    v = AdvancedEBPFVerifier()
    mounts = "cgroup2 /sys/fs/cgroup cgroup2 ro,nosuid 0 0\n"
    with patch('builtins.open', mock_open(read_data=mounts)):
        result = v.check_cgroup2_unified()
    check("cgroup2: fails when mount options say read-only", result is False)


def test_cgroup2_warns_when_absent():
    v = AdvancedEBPFVerifier()
    mounts = "tmpfs /tmp tmpfs rw 0 0\n"
    with patch('builtins.open', mock_open(read_data=mounts)):
        result = v.check_cgroup2_unified()
    check("cgroup2: returns False when no cgroup2 mount exists at all",
          result is False)


def test_bpf_helpers_never_returns_true():
    v = AdvancedEBPFVerifier()
    with patch('os.path.exists', return_value=True), \
         patch('builtins.open',
               mock_open(read_data="bpf_map_lookup_elem some other text")):
        result = v.check_bpf_helpers()
    check("bpf_helpers: NEVER returns True, even when the old string "
          "match would have -- it is not evidence of helper availability",
          result is not True, f"got {result}")


def test_bpf_helpers_returns_none_not_true_when_file_absent():
    v = AdvancedEBPFVerifier()
    with patch('os.path.exists', return_value=False):
        result = v.check_bpf_helpers()
    check("bpf_helpers: returns None (unknown), not True, when file absent",
          result is None, f"got {result}")


def test_kprobes_pass_when_enabled():
    v = AdvancedEBPFVerifier()
    def exists_side_effect(path):
        return path == "/sys/kernel/debug/kprobes/enabled"
    with patch('os.path.exists', side_effect=exists_side_effect), \
         patch('builtins.open', mock_open(read_data="1")):
        result = v.check_kprobes()
    check("kprobes: PASS when enabled=1", result is True)


def test_kprobes_fail_when_nothing_accessible():
    v = AdvancedEBPFVerifier()
    with patch('os.path.exists', return_value=False):
        result = v.check_kprobes()
    check("kprobes: FAILS when neither kprobes nor tracefs is accessible",
          result is False)


def test_run_preflight_does_not_crash_on_none_from_bpf_helpers():
    v = AdvancedEBPFVerifier()
    with patch.object(platform, 'release', return_value='5.15.0-generic'), \
         patch('os.path.exists', return_value=False), \
         patch('builtins.open', mock_open(read_data="tmpfs / tmpfs rw 0 0\n")):
        try:
            v.run_preflight_checks()
            check("run_preflight_checks: does not crash on None from "
                  "check_bpf_helpers", True)
        except Exception as e:
            check("run_preflight_checks: does not crash on None from "
                  "check_bpf_helpers", False, f"raised {e!r}")


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
