#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
tests/test_tenant_file_cleaner.py

Tests remediation/tenant_file_cleaner.py against the PASS/FAIL criteria
written in REMEDIATION_CLEARING_PLAN.md Part 1 BEFORE the code existed:

  PASS = foreign pre-existing files identified, deleted, logged BEFORE
         deletion; current-session files untouched.
  FAIL = current-session files deleted, deletion before logging, or
         foreign files missed.

Run: python3 tests/test_tenant_file_cleaner.py
"""
import sys
import os
import json
import time
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from remediation import tenant_file_cleaner as t

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    if cond:
        PASSED.append(name); print(f"[PASS] {name}")
    else:
        FAILED.append(name); print(f"[FAIL] {name} {detail}")


def make_tree():
    """Fake shared temp dir: 2 old (foreign, 16d matching Vast.ai), 2 new."""
    d = tempfile.mkdtemp()
    old_ts = time.time() - 86400 * 16
    for n in ["tenant_a_data.bin", "tenant_a_cache.tmp"]:
        p = os.path.join(d, n)
        open(p, "w").write("x" * 100)
        os.utime(p, (old_ts, old_ts))
    for n in ["our_file.txt", "our_scratch.log"]:
        open(os.path.join(d, n), "w").write("y" * 50)
    return d


def test_scan_finds_only_foreign():
    d = make_tree()
    try:
        found = t.scan(time.time() - 60, scan_dirs=[d])
        names = sorted(os.path.basename(f["path"]) for f in found)
        check("SCAN: finds exactly the 2 pre-session files",
              names == ["tenant_a_cache.tmp", "tenant_a_data.bin"],
              f"got {names}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_scan_never_flags_current_session():
    d = make_tree()
    try:
        found = t.scan(time.time() - 60, scan_dirs=[d])
        ours = [f for f in found if "our_" in f["path"]]
        check("SCAN NEGATIVE: current-session files never flagged",
              len(ours) == 0, f"flagged {ours}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_scan_reports_age():
    d = make_tree()
    try:
        found = t.scan(time.time() - 60, scan_dirs=[d])
        check("SCAN: reports age in days (~16d as in the Vast.ai finding)",
              found and 15 < found[0]["age_days"] < 17,
              f"got {found[0]['age_days'] if found else 'none'}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_dry_run_deletes_nothing():
    d = make_tree()
    try:
        t.DRY_RUN = True
        res = t.clean(session_start_ts=time.time() - 60, scan_dirs=[d],
                      emit_fn=lambda e: None)
        still = sorted(os.listdir(d))
        check("DRY_RUN: reports foreign files but deletes nothing",
              res["status"] == "DRY_RUN_NO_ACTION" and len(still) == 4,
              f"status={res['status']} remaining={still}")
    finally:
        t.DRY_RUN = True
        shutil.rmtree(d, ignore_errors=True)


def test_approval_gate_blocks():
    d = make_tree()
    try:
        t.DRY_RUN = False
        t.HUMAN_APPROVAL_REQUIRED = True
        t.APPROVAL_FILE = "/tmp/definitely_not_here_xyz"
        res = t.clean(session_start_ts=time.time() - 60, scan_dirs=[d],
                      emit_fn=lambda e: None)
        still = sorted(os.listdir(d))
        check("APPROVAL GATE: blocks deletion with no approval file",
              res["status"] == "SKIPPED_HUMAN_REQUIRED" and len(still) == 4,
              f"status={res['status']} remaining={still}")
    finally:
        t.DRY_RUN = True
        t.APPROVAL_FILE = "/tmp/watchdog_approve_action"
        shutil.rmtree(d, ignore_errors=True)


def test_full_delete_with_approval():
    d = make_tree()
    ledger = tempfile.mktemp()
    appr = tempfile.mktemp()
    open(appr, "w").write("tenant_file_clean")
    try:
        t.DRY_RUN = False
        t.HUMAN_APPROVAL_REQUIRED = True
        t.APPROVAL_FILE = appr
        res = t.clean(session_start_ts=time.time() - 60, scan_dirs=[d],
                      ledger_path=ledger, emit_fn=lambda e: None)
        still = sorted(os.listdir(d))
        check("DELETE: removes foreign files when approved",
              len(res["deleted"]) == 2, f"deleted {res['deleted']}")
        check("DELETE: leaves current-session files untouched",
              still == ["our_file.txt", "our_scratch.log"], f"got {still}")
    finally:
        t.DRY_RUN = True
        t.APPROVAL_FILE = "/tmp/watchdog_approve_action"
        shutil.rmtree(d, ignore_errors=True)
        for p in (ledger, appr):
            try: os.remove(p)
            except OSError: pass


def test_ledger_written_before_delete():
    """Core discipline: intent entry must precede result entry."""
    d = make_tree()
    ledger = tempfile.mktemp()
    appr = tempfile.mktemp()
    open(appr, "w").write("tenant_file_clean")
    try:
        t.DRY_RUN = False
        t.HUMAN_APPROVAL_REQUIRED = True
        t.APPROVAL_FILE = appr
        t.clean(session_start_ts=time.time() - 60, scan_dirs=[d],
                ledger_path=ledger, emit_fn=lambda e: None)
        lines = [json.loads(l) for l in open(ledger) if l.strip()]
        events = [l["event"] for l in lines]
        fi = events.index("TENANT_FILE_DELETE_INTENT")
        fr = events.index("TENANT_FILE_DELETE_RESULT")
        check("LEDGER: intent entry written BEFORE result entry",
              fi < fr, f"intent@{fi} result@{fr}")
        check("LEDGER: intent records path, mtime, size, mode, uid",
              all(k in lines[fi]
                  for k in ("path", "mtime", "size_bytes", "mode", "uid")),
              f"got keys {list(lines[fi].keys())}")
        check("LEDGER: two entries per deleted file",
              len(lines) == 4, f"got {len(lines)} lines for 2 files")
    finally:
        t.DRY_RUN = True
        t.APPROVAL_FILE = "/tmp/watchdog_approve_action"
        shutil.rmtree(d, ignore_errors=True)
        for p in (ledger, appr):
            try: os.remove(p)
            except OSError: pass


def test_ledger_failure_aborts_delete():
    """If the ledger cannot be written, the file must NOT be deleted."""
    d = make_tree()
    appr = tempfile.mktemp()
    open(appr, "w").write("tenant_file_clean")
    orig = t._write_ledger
    try:
        t.DRY_RUN = False
        t.HUMAN_APPROVAL_REQUIRED = True
        t.APPROVAL_FILE = appr
        t._write_ledger = lambda *a, **k: False
        res = t.clean(session_start_ts=time.time() - 60, scan_dirs=[d],
                      emit_fn=lambda e: None)
        still = sorted(os.listdir(d))
        check("LEDGER FAILURE: aborts deletion rather than deleting unlogged",
              len(res["deleted"]) == 0 and len(still) == 4,
              f"deleted={res['deleted']} remaining={still}")
        check("LEDGER FAILURE: reason recorded in failed list",
              res["failed"] and "LEDGER_WRITE_FAILED" in
              res["failed"][0]["reason"], f"got {res['failed']}")
    finally:
        t._write_ledger = orig
        t.DRY_RUN = True
        t.APPROVAL_FILE = "/tmp/watchdog_approve_action"
        shutil.rmtree(d, ignore_errors=True)
        try: os.remove(appr)
        except OSError: pass


def test_protected_paths_never_touched():
    d = make_tree()
    try:
        old = time.time() - 86400 * 20
        p = os.path.join(d, "protected_marker")
        open(p, "w").write("x")
        os.utime(p, (old, old))
        t.PROTECTED = t.PROTECTED | {p}
        found = t.scan(time.time() - 60, scan_dirs=[d])
        check("PROTECTED: protected paths excluded from scan results",
              p not in [f["path"] for f in found])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_missing_dir_is_safe():
    check("SCAN: nonexistent dir returns empty, does not raise",
          t.scan(time.time(), scan_dirs=["/definitely/not/real"]) == [])


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_"):
            try:
                _f()
            except Exception as e:
                check(_n, False, f"EXCEPTION {e!r}")
    print("\n" + "=" * 60)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    for f in FAILED:
        print(f"  - {f}")
    print("=" * 60)
    sys.exit(1 if FAILED else 0)
