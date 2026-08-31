#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_watchdog_daemon.py

Tests the runtime daemon end-to-end with a FAKE nvidia-smi (no GPU needed):
telemetry collection, detector wiring, correlator feed, and evidence output
(CSV/JSONL/metrics/README). Also tests dry-run and graceful behavior when
nvidia-smi is absent.

Run standalone: python3 tests/test_watchdog_daemon.py
Or via suite:   python3 tests/run_all.py (once registered in TEST_FILES).
"""
import os
import sys
import json
import shutil
import tempfile
from types import SimpleNamespace

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# import the daemon module (lives in runtime/)
from runtime.watchdog_daemon import (
    WatchdogDaemon, query_nvidia_smi, normalize, DetectorRegistry, SMI_FIELDS,
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


# --- fake nvidia-smi runners ------------------------------------------------
def fake_smi_1gpu(cmd, **kw):
    # one GPU row matching SMI_FIELDS order
    return SimpleNamespace(returncode=0,
        stdout="0, 194.0, 65, 0, 629, 1800, 1593, 5, 12, 0\n")


def fake_smi_4gpu(cmd, **kw):
    lines = []
    for i in range(4):
        lines.append(f"{i}, 194.0, 65, 0, 629, 1800, 1593, 5, {i*3}, 0")
    return SimpleNamespace(returncode=0, stdout="\n".join(lines) + "\n")


def fake_smi_hammering(cmd, **kw):
    # rising/accelerating ECC to try to trip the rowhammer precursor
    fake_smi_hammering.n = getattr(fake_smi_hammering, "n", 0) + 1
    corrected = fake_smi_hammering.n ** 2 * 5
    return SimpleNamespace(returncode=0,
        stdout=f"0, 194.0, 65, 0, 629, 1800, 1593, 5, {corrected}, 0\n")


def no_smi(cmd, **kw):
    raise FileNotFoundError("nvidia-smi not found")


# --- telemetry primitives ---------------------------------------------------
def test_query_parses_gpu_rows():
    rows = query_nvidia_smi(runner=fake_smi_4gpu)
    check("daemon: parses 4 GPU rows", len(rows) == 4, f"got {len(rows)}")


def test_query_missing_smi_is_empty():
    rows = query_nvidia_smi(runner=no_smi)
    check("daemon: missing nvidia-smi -> empty list, no crash", rows == [], f"got {rows}")


def test_normalize_maps_fields():
    rows = query_nvidia_smi(runner=fake_smi_1gpu)
    s = normalize(rows[0], "t0")
    check("daemon: normalize maps power + ecc",
          s["power_watts"] == 194.0 and s["ecc_corrected_total"] == 12.0, f"got {s}")


# --- detector registry ------------------------------------------------------
def test_registry_loads_or_skips_gracefully():
    reg = DetectorRegistry(repo_root=_REPO_ROOT)
    summ = reg.summary()
    # In this test harness the swarm agents may or may not be importable;
    # either way the registry must not crash and must record the outcome.
    check("daemon: registry produces loaded+skipped lists without crashing",
          isinstance(summ["loaded"], list) and isinstance(summ["skipped"], list),
          f"got {summ}")


def test_registry_run_all_never_crashes():
    reg = DetectorRegistry(repo_root=_REPO_ROOT)
    s = normalize(query_nvidia_smi(runner=fake_smi_1gpu)[0], "t0")
    alerts = reg.run_all(s)  # must return a list regardless of what loaded
    check("daemon: run_all returns a list of alerts", isinstance(alerts, list),
          f"got {type(alerts)}")


# --- dry run ----------------------------------------------------------------
def test_dry_run_writes_nothing():
    tmp = tempfile.mkdtemp(prefix="wd_dry_")
    try:
        d = WatchdogDaemon(repo_root=tmp, smi_runner=fake_smi_1gpu)
        plan = d.dry_run()
        check("daemon: dry-run returns a plan with mode DRY_RUN",
              plan["mode"] == "DRY_RUN", f"got {plan.get('mode')}")
        # dry run must not create the evidence dir
        check("daemon: dry-run writes nothing",
              not os.path.exists(d.evidence_dir), "evidence dir created in dry-run")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- live run end-to-end ----------------------------------------------------
def test_live_run_writes_evidence():
    tmp = tempfile.mkdtemp(prefix="wd_live_")
    try:
        d = WatchdogDaemon(repo_root=tmp, interval=0.0, duration=None,
                           smi_runner=fake_smi_4gpu)
        # cap iterations via a fake sleep that raises after N cycles
        state = {"n": 0}
        def fake_sleep(_):
            state["n"] += 1
            if state["n"] >= 3:
                # emulate duration end by setting duration retroactively
                d.duration = 0.0
        # give it a start so the duration check trips after fake_sleep
        import time as _t
        d.duration = 999  # will be overridden by fake_sleep
        result = d.run(sleep=fake_sleep)
        check("daemon: live run completes",
              result["status"] == "COMPLETE", f"got {result}")
        check("daemon: collected 4 GPUs x >=1 cycle of samples",
              result["samples"] >= 4, f"got {result['samples']}")
        # evidence files exist
        for fname in ("telemetry.csv", "alerts.jsonl", "incidents.jsonl",
                      "metrics.json", "README.md"):
            path = os.path.join(d.evidence_dir, fname)
            check(f"daemon: wrote {fname}", os.path.exists(path),
                  f"missing {path}")
        # metrics.json is valid + has counts
        with open(os.path.join(d.evidence_dir, "metrics.json")) as f:
            m = json.load(f)
        check("daemon: metrics.json records samples",
              m["samples_collected"] == result["samples"], f"got {m}")
        # telemetry.csv has a header + rows
        with open(os.path.join(d.evidence_dir, "telemetry.csv")) as f:
            csv_lines = f.read().strip().splitlines()
        check("daemon: telemetry.csv has header + data rows",
              len(csv_lines) >= 5 and csv_lines[0].startswith("timestamp"),
              f"got {len(csv_lines)} lines")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_live_run_no_gpu_is_honest():
    tmp = tempfile.mkdtemp(prefix="wd_nogpu_")
    try:
        d = WatchdogDaemon(repo_root=tmp, interval=0.0, smi_runner=no_smi)
        state = {"n": 0}
        def fake_sleep(_):
            state["n"] += 1
            if state["n"] >= 2:
                d.duration = 0.0
        d.duration = 999
        result = d.run(sleep=fake_sleep)
        check("daemon: no-GPU run completes with 0 samples (honest)",
              result["status"] == "COMPLETE" and result["samples"] == 0,
              f"got {result}")
        # still writes the evidence + metrics (recording the honest zero)
        check("daemon: no-GPU run still writes metrics",
              os.path.exists(os.path.join(d.evidence_dir, "metrics.json")),
              "no metrics written")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_readme_written_with_honest_status():
    tmp = tempfile.mkdtemp(prefix="wd_readme_")
    try:
        d = WatchdogDaemon(repo_root=tmp, interval=0.0, smi_runner=fake_smi_1gpu)
        state = {"n": 0}
        def fake_sleep(_):
            state["n"] += 1
            if state["n"] >= 2:
                d.duration = 0.0
        d.duration = 999
        d.run(sleep=fake_sleep)
        with open(os.path.join(d.evidence_dir, "README.md")) as f:
            readme = f.read()
        check("daemon: README carries the honest 'evidence not validation' note",
              "evidence" in readme.lower() and "gated" in readme.lower(),
              "README missing honest status")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
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
