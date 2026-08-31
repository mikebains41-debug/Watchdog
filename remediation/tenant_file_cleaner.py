#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
remediation/tenant_file_cleaner.py

Implements PART 1 of REMEDIATION_CLEARING_PLAN.md: tenant /tmp residual
detection and removal.

FINDING THIS ADDRESSES
    Vast.ai instance 41986069, 2026-06-21: 5/5 scans found leftover files
    from a previous tenant in shared /tmp overlay storage, 16 days old.
    RunPod comparison: 2/2 scans clean.

WHY IT IS FIXABLE (unlike VRAM residual)
    uid_mapping_note.md records /proc/self/uid_map as "0 0 4294967295" --
    container UID 0 maps directly to host UID 0, no userns-remap. Current
    session root therefore likely holds delete permission on these files.
    These are real files on a real filesystem. This is NOT the VRAM case,
    where the residual is an accounting figure with zero recoverable bytes.
    Do not merge the two in any doc or deck.

SAFETY MODEL (ported from todo/module21.py)
    DRY_RUN defaults to TRUE. Nothing is deleted unless WD_DRY_RUN=false
    AND human approval is granted via the approval file. A scan alone is
    always safe to run.

LEDGER DISCIPLINE
    Every deletion writes TWO ledger entries:
      1. BEFORE the delete -- path, mtime, size, mode, uid, detected_at
      2. AFTER the delete  -- confirmation, or failure with exact reason
    An action logged only on success is not auditable. Logging first means
    even a wrong deletion is fully traceable.

HONEST LIMITS
    - Age heuristic only. A file predating session start is treated as
      foreign. A previous tenant who wrote files seconds before your
      session began would not be caught.
    - Cannot read the true owning tenant; container UID is not a tenant ID.
    - Scans only /tmp and /dev/shm, not every possible shared path.
    - A clean scan does not prove the provider isolates tenants properly.
"""

import json
import os
import shutil
import stat
import time
from datetime import datetime, timezone

DRY_RUN = os.environ.get("WD_DRY_RUN", "true").lower() != "false"
HUMAN_APPROVAL_REQUIRED = os.environ.get(
    "WD_HUMAN_APPROVAL", "true").lower() != "false"
APPROVAL_FILE = "/tmp/watchdog_approve_action"
LEDGER_PATH = os.environ.get(
    "WD_TENANT_LEDGER", "tenant_cleanup_ledger.jsonl")

SCAN_DIRS = ["/tmp", "/dev/shm"]

PROTECTED = {
    APPROVAL_FILE,
    "/tmp/.X11-unix",
    "/tmp/.ICE-unix",
    "/tmp/.XIM-unix",
    "/tmp/.font-unix",
    "/tmp/.Test-unix",
}
PROTECTED_PREFIXES = ("/tmp/systemd-", "/tmp/snap-", "/dev/shm/nvidia")


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _write_ledger(entry, ledger_path=LEDGER_PATH, _open=open):
    """Append one JSON line. Returns True/False -- never raises.
    A ledger write failure must BLOCK the deletion, not crash the scan."""
    try:
        with _open(ledger_path, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return True
    except Exception:
        return False


def approval_granted(action):
    """Same contract as module21.approval_granted."""
    if not HUMAN_APPROVAL_REQUIRED:
        return True
    try:
        with open(APPROVAL_FILE) as fh:
            approved = fh.read().strip()
        return approved == action or approved == "any"
    except (FileNotFoundError, PermissionError, OSError):
        return False


def _is_protected(path):
    if path in PROTECTED:
        return True
    return any(path.startswith(p) for p in PROTECTED_PREFIXES)


def scan(session_start_ts, scan_dirs=None, _walk=os.walk, _stat=os.stat):
    """Return foreign/stale items predating session start. Read-only."""
    dirs = scan_dirs if scan_dirs is not None else SCAN_DIRS
    found = []
    for base in dirs:
        if not os.path.isdir(base):
            continue
        for root, dirnames, filenames in _walk(base):
            for name in list(dirnames) + list(filenames):
                path = os.path.join(root, name)
                if _is_protected(path):
                    continue
                try:
                    st = _stat(path)
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                if st.st_mtime >= session_start_ts:
                    continue
                found.append({
                    "path": path,
                    "mtime": st.st_mtime,
                    "mtime_iso": datetime.fromtimestamp(
                        st.st_mtime, timezone.utc).isoformat(),
                    "age_days": round(
                        (session_start_ts - st.st_mtime) / 86400.0, 2),
                    "size_bytes": st.st_size,
                    "mode": stat.filemode(st.st_mode),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "is_dir": stat.S_ISDIR(st.st_mode),
                })
    return found


def clean(session_start_ts=None, scan_dirs=None, ledger_path=LEDGER_PATH,
          emit_fn=print, _rmtree=shutil.rmtree, _remove=os.remove,
          _walk=os.walk, _stat=os.stat):
    """Scan, log, then delete confirmed-stale foreign items."""
    if session_start_ts is None:
        session_start_ts = time.time()

    items = scan(session_start_ts, scan_dirs=scan_dirs,
                 _walk=_walk, _stat=_stat)

    result = {
        "action": "tenant_file_clean",
        "timestamp": _now_iso(),
        "session_start_ts": session_start_ts,
        "scanned_dirs": scan_dirs if scan_dirs is not None else SCAN_DIRS,
        "foreign_found": len(items),
        "dry_run": DRY_RUN,
        "human_approval_required": HUMAN_APPROVAL_REQUIRED,
        "deleted": [],
        "failed": [],
        "status": None,
    }

    if not items:
        result["status"] = "CLEAN_NO_FOREIGN_FILES"
        emit_fn({"event": "TENANT_SCAN_CLEAN",
                 "dirs": result["scanned_dirs"],
                 "note": "no files predating session start"})
        return result

    emit_fn({"event": "TENANT_FOREIGN_FILES_DETECTED",
             "count": len(items),
             "oldest_age_days": max(i["age_days"] for i in items),
             "note": "files predating session start in shared temp dirs"})

    if DRY_RUN:
        result["status"] = "DRY_RUN_NO_ACTION"
        emit_fn({"event": "DRY_RUN_TENANT_CLEAN",
                 "would_delete": len(items),
                 "note": "Set WD_DRY_RUN=false and grant approval to enable"})
        return result

    if not approval_granted("tenant_file_clean"):
        result["status"] = "SKIPPED_HUMAN_REQUIRED"
        emit_fn({"event": "TENANT_CLEAN_AWAITING_APPROVAL",
                 "approval_file": APPROVAL_FILE,
                 "note": "echo tenant_file_clean > " + APPROVAL_FILE})
        return result

    for item in items:
        pre = dict(item)
        pre["event"] = "TENANT_FILE_DELETE_INTENT"
        pre["detected_at"] = _now_iso()
        if not _write_ledger(pre, ledger_path):
            result["failed"].append({
                "path": item["path"],
                "reason": "LEDGER_WRITE_FAILED_DELETE_ABORTED",
            })
            continue

        try:
            if item["is_dir"]:
                _rmtree(item["path"])
            else:
                _remove(item["path"])
            ok, reason = True, None
        except Exception as e:
            ok, reason = False, f"{type(e).__name__}: {e}"

        _write_ledger({
            "event": "TENANT_FILE_DELETE_RESULT",
            "path": item["path"],
            "deleted": ok,
            "reason": reason,
            "completed_at": _now_iso(),
        }, ledger_path)

        if ok:
            result["deleted"].append(item["path"])
        else:
            result["failed"].append({"path": item["path"], "reason": reason})

    result["status"] = ("COMPLETED" if not result["failed"]
                        else "COMPLETED_WITH_FAILURES")
    emit_fn({"event": "TENANT_CLEAN_COMPLETE",
             "deleted": len(result["deleted"]),
             "failed": len(result["failed"]),
             "status": result["status"]})
    return result


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(
        description="Scan and optionally clean tenant residual files")
    ap.add_argument("--scan-only", action="store_true",
                    help="scan and report, never delete (always safe)")
    ap.add_argument("--session-start", type=float, default=None,
                    help="unix ts of session start (default: now)")
    args = ap.parse_args()

    start = args.session_start if args.session_start else time.time()

    if args.scan_only:
        found = scan(start)
        print(f"[TENANT SCAN] {len(found)} item(s) predating session start")
        for f in found[:50]:
            print(f"  {f['mtime_iso']}  {f['age_days']:>7.2f}d  "
                  f"{f['size_bytes']:>10}B  {f['mode']}  {f['path']}")
        if len(found) > 50:
            print(f"  ... and {len(found) - 50} more")
    else:
        res = clean(session_start_ts=start)
        print(json.dumps(res, indent=2))
