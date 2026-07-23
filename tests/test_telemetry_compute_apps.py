# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
tests/test_telemetry_compute_apps.py

Tests for the fix to agent/telemetry.py: sample_gpu() now always sets
row['compute_apps'], which was previously never set at all. Before this
fix, VRAMResidualDetector (strict=True by default, never overridden by
watchdog.py) would raise on the very first sample of any real run.

Run: python tests/test_telemetry_compute_apps.py
"""

import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from agent.telemetry import sample_compute_apps, sample_gpu, QUERY_FIELDS
from detection.engines import VRAMResidualDetector, VRAMResidualUnavailable

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def fake_completed_process(stdout):
    class R:
        pass
    r = R()
    r.stdout = stdout
    r.returncode = 0
    return r


def test_parses_multi_gpu_multi_process_output():
    fake_out = (
        "GPU-aaaa, 100, 2048\n"
        "GPU-aaaa, 101, 4096\n"
        "GPU-bbbb, 200, 8192\n"
    )
    with patch('subprocess.run', return_value=fake_completed_process(fake_out)):
        result = sample_compute_apps()
    check("parses multiple processes on the same GPU correctly",
          result.get('GPU-aaaa') == [{'pid': 100, 'used_memory': 2048.0},
                                      {'pid': 101, 'used_memory': 4096.0}],
          f"got {result}")
    check("parses a different GPU's process into its own bucket",
          result.get('GPU-bbbb') == [{'pid': 200, 'used_memory': 8192.0}],
          f"got {result}")


def test_empty_output_gives_empty_dict_not_crash():
    with patch('subprocess.run', return_value=fake_completed_process("")):
        result = sample_compute_apps()
    check("empty nvidia-smi output -> empty dict, no crash",
          result == {}, f"got {result}")


def test_malformed_line_skipped_gracefully():
    fake_out = "GPU-aaaa, not_a_pid, not_a_number\nGPU-bbbb, 55, 1024\n"
    with patch('subprocess.run', return_value=fake_completed_process(fake_out)):
        result = sample_compute_apps()
    check("malformed line is skipped, well-formed line still parsed",
          'GPU-aaaa' not in result and result.get('GPU-bbbb') == [{'pid': 55, 'used_memory': 1024.0}],
          f"got {result}")


def test_subprocess_exception_gives_empty_dict_not_crash():
    def raise_err(*a, **kw):
        raise FileNotFoundError("nvidia-smi not found")
    with patch('subprocess.run', side_effect=raise_err):
        result = sample_compute_apps()
    check("subprocess failure -> empty dict, does not propagate",
          result == {}, f"got {result}")


def _fake_query_gpu_line(index, uuid, power=80.0, util=0, mem=100):
    vals = {
        'timestamp': '2026/07/19 00:00:00',
        'index': str(index),
        'uuid': uuid,
        'name': 'NVIDIA H200',
        'power.draw': str(power),
        'power.limit': '700',
        'utilization.gpu': str(util),
        'utilization.memory': '0',
        'memory.used': str(mem),
        'memory.free': '100000',
        'memory.total': '141000',
        'clocks.sm': '1980',
        'clocks.mem': '2619',
        'clocks.gr': '1980',
        'temperature.gpu': '40',
        'pstate': 'P0',
        'ecc.errors.corrected.volatile.total': '0',
        'ecc.errors.uncorrected.volatile.total': '0',
    }
    return ",".join(vals[f] for f in QUERY_FIELDS)


def test_sample_gpu_always_sets_compute_apps_key_even_when_empty():
    """The core regression: this key must exist, even with no processes,
    since a MISSING key (not an empty list) is what crashes
    VRAMResidualDetector in strict mode."""
    gpu_line = _fake_query_gpu_line(0, 'GPU-aaaa')

    def fake_run(cmd, **kw):
        if '--query-compute-apps' in cmd[1]:
            return fake_completed_process("")
        return fake_completed_process(gpu_line)

    with patch('subprocess.run', side_effect=fake_run):
        rows = sample_gpu()

    check("sample_gpu returns one row", len(rows) == 1, f"got {rows}")
    check("compute_apps key is present (not missing) even with no processes",
          'compute_apps' in rows[0], f"row keys: {list(rows[0].keys())}")
    check("compute_apps is an empty list, not None, when nothing is running",
          rows[0]['compute_apps'] == [], f"got {rows[0].get('compute_apps')}")


def test_sample_gpu_joins_compute_apps_to_correct_gpu_by_uuid():
    """Two GPUs, two different process lists. Confirm each row gets ONLY
    its own GPU's processes, not the other's, not both merged."""
    line_a = _fake_query_gpu_line(0, 'GPU-aaaa')
    line_b = _fake_query_gpu_line(1, 'GPU-bbbb')
    multi_gpu_output = line_a + "\n" + line_b

    apps_output = "GPU-aaaa, 111, 5000\nGPU-bbbb, 222, 9000\n"

    def fake_run(cmd, **kw):
        if '--query-compute-apps' in cmd[1]:
            return fake_completed_process(apps_output)
        return fake_completed_process(multi_gpu_output)

    with patch('subprocess.run', side_effect=fake_run):
        rows = sample_gpu()

    check("two GPU rows returned", len(rows) == 2, f"got {len(rows)} rows")
    row_a = next(r for r in rows if r['uuid'] == 'GPU-aaaa')
    row_b = next(r for r in rows if r['uuid'] == 'GPU-bbbb')
    check("GPU-aaaa's row gets only GPU-aaaa's process",
          row_a['compute_apps'] == [{'pid': 111, 'used_memory': 5000.0}],
          f"got {row_a['compute_apps']}")
    check("GPU-bbbb's row gets only GPU-bbbb's process, not GPU-aaaa's",
          row_b['compute_apps'] == [{'pid': 222, 'used_memory': 9000.0}],
          f"got {row_b['compute_apps']}")


def test_regression_numeric_fields_still_coerced_correctly():
    """Confirm the compute_apps addition didn't disturb existing behavior."""
    gpu_line = _fake_query_gpu_line(0, 'GPU-aaaa', power=123.5, util=42, mem=5000)

    def fake_run(cmd, **kw):
        if '--query-compute-apps' in cmd[1]:
            return fake_completed_process("")
        return fake_completed_process(gpu_line)

    with patch('subprocess.run', side_effect=fake_run):
        rows = sample_gpu()

    check("power.draw still coerced to float", rows[0]['power.draw'] == 123.5,
          f"got {rows[0]['power.draw']!r}")
    check("utilization.gpu still coerced to float", rows[0]['utilization.gpu'] == 42.0,
          f"got {rows[0]['utilization.gpu']!r}")


def test_end_to_end_no_longer_crashes_vram_residual_detector():
    """The exact bug: VRAMResidualDetector(strict=True) against a real
    row from sample_gpu(). Before this fix this raised on line 1."""
    gpu_line = _fake_query_gpu_line(0, 'GPU-aaaa')

    def fake_run(cmd, **kw):
        if '--query-compute-apps' in cmd[1]:
            return fake_completed_process("")
        return fake_completed_process(gpu_line)

    with patch('subprocess.run', side_effect=fake_run):
        rows = sample_gpu()

    d = VRAMResidualDetector(strict=True)
    try:
        result = d.update(rows[0])
        check("VRAMResidualDetector(strict=True) no longer raises on a "
              "real sample_gpu() row", True)
    except VRAMResidualUnavailable as e:
        check("VRAMResidualDetector(strict=True) no longer raises on a "
              "real sample_gpu() row", False, f"still raised: {e}")


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
