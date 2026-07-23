# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
tests/test_telemetry_sampler_wiring.py

Tests for wiring DeltaTimedSampler (built earlier, never connected) into
TelemetryCollector. Proves actual_interval_ms is measured and appears in
both the CSV output and each row passed to on_sample -- not silently
assumed from self.sample_hz.

Run: python tests/test_telemetry_sampler_wiring.py
"""

import sys
import os
import csv
import tempfile
import shutil
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from agent.telemetry import TelemetryCollector, QUERY_FIELDS

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"[PASS] {name}")
    else:
        FAILED.append(name)
        print(f"[FAIL] {name} {detail}")


def fake_proc(stdout=""):
    class R:
        pass
    r = R()
    r.stdout = stdout
    r.returncode = 0
    return r


def _fake_query_gpu_line():
    vals = {
        'timestamp': '2026/07/19 00:00:00', 'index': '0', 'uuid': 'GPU-aaaa',
        'name': 'NVIDIA H200', 'power.draw': '80.0', 'power.limit': '700',
        'utilization.gpu': '0', 'utilization.memory': '0', 'memory.used': '100',
        'memory.free': '100000', 'memory.total': '141000', 'clocks.sm': '1980',
        'clocks.mem': '2619', 'clocks.gr': '1980', 'temperature.gpu': '40',
        'pstate': 'P0', 'ecc.errors.corrected.volatile.total': '0',
        'ecc.errors.uncorrected.volatile.total': '0',
    }
    return ",".join(vals[f] for f in QUERY_FIELDS)


def test_timer_attribute_exists_and_is_delta_timed_sampler():
    tmpdir = tempfile.mkdtemp()
    try:
        c = TelemetryCollector(output_dir=tmpdir)
        check("TelemetryCollector has a .timer attribute",
              hasattr(c, 'timer'), f"attrs: {dir(c)}")
        check(".timer has a .stats() method (is a real DeltaTimedSampler)",
              hasattr(c.timer, 'stats') and callable(c.timer.stats))
    finally:
        shutil.rmtree(tmpdir)


def test_actual_interval_ms_appears_in_csv_output():
    """The core proof: run a short real collection loop against mocked
    nvidia-smi, and confirm the CSV has real, non-null interval values --
    not the requested rate silently assumed."""
    tmpdir = tempfile.mkdtemp()
    try:
        gpu_line = _fake_query_gpu_line()

        def fake_run(cmd, **kw):
            if '--query-compute-apps' in cmd[1]:
                return fake_proc("")
            return fake_proc(gpu_line)

        c = TelemetryCollector(sample_hz=50, output_dir=tmpdir)
        with patch('subprocess.run', side_effect=fake_run):
            csv_path = c.start(duration_seconds=0.3)

        check("collection produced at least one sample",
              c.sample_count > 0, f"sample_count={c.sample_count}")

        with open(csv_path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        check("CSV has 'actual_interval_ms' as a real column",
              'actual_interval_ms' in reader.fieldnames,
              f"fieldnames: {reader.fieldnames}")
        check("CSV has at least one row", len(rows) > 0, f"got {len(rows)}")

        non_first_rows = [r for r in rows if r['actual_interval_ms'] != '']
        check("at least the non-first samples have a real numeric "
              "interval value (proves it's measured, not blank/assumed)",
              len(non_first_rows) > 0, f"rows: {rows}")

        if non_first_rows:
            val = float(non_first_rows[0]['actual_interval_ms'])
            check("measured interval is a plausible positive number of ms",
                  0 < val < 10000, f"got {val}")
    finally:
        shutil.rmtree(tmpdir)


def test_actual_interval_ms_reaches_on_sample_callback():
    """Confirm the value isn't just written to CSV but also reaches
    whatever downstream code (e.g. DetectionPipeline) consumes on_sample
    -- since detectors could eventually use this to sanity-check their
    own timing assumptions."""
    tmpdir = tempfile.mkdtemp()
    try:
        gpu_line = _fake_query_gpu_line()

        def fake_run(cmd, **kw):
            if '--query-compute-apps' in cmd[1]:
                return fake_proc("")
            return fake_proc(gpu_line)

        received_rows = []
        c = TelemetryCollector(sample_hz=50, output_dir=tmpdir,
                                on_sample=lambda row: received_rows.append(row))
        with patch('subprocess.run', side_effect=fake_run):
            c.start(duration_seconds=0.3)

        check("on_sample received rows with 'actual_interval_ms' key present",
              len(received_rows) > 0 and
              all('actual_interval_ms' in r for r in received_rows),
              f"got {len(received_rows)} rows")
    finally:
        shutil.rmtree(tmpdir)


def test_final_stats_report_real_achieved_hz_not_requested():
    """Regression against the exact bug: requested Hz and achieved Hz
    should be reported as DISTINCT numbers, not the same assumed value."""
    tmpdir = tempfile.mkdtemp()
    try:
        gpu_line = _fake_query_gpu_line()

        def fake_run(cmd, **kw):
            if '--query-compute-apps' in cmd[1]:
                return fake_proc("")
            return fake_proc(gpu_line)

        c = TelemetryCollector(sample_hz=1000, output_dir=tmpdir)
        with patch('subprocess.run', side_effect=fake_run):
            c.start(duration_seconds=0.3)

        stats = c.timer.stats()
        check("final stats report a measured achieved_hz",
              stats['achieved_hz'] is not None, f"got {stats}")
        check("achieved_hz is NOT silently equal to the unrealistic "
              "requested 1000Hz -- proves it's measured, not assumed",
              stats['achieved_hz'] != 1000, f"got {stats['achieved_hz']}")
    finally:
        shutil.rmtree(tmpdir)


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
