#!/usr/bin/env python3
"""
Watchdog -- HANDOVER CAPTURE. Run this as the FIRST command of every rental,
before touching anything else. About 30 seconds.

WHY: on a marketplace like Vast.ai you are handed a machine the previous tenant
just released. Whatever they left behind is visible in the first seconds --
after you run a workload, it is your own state you are measuring.

Captures (tests 1-7):
  1. tenant leftovers      -- files in shared/temp paths owned by another uid
  2. NVLink counters       -- non-zero at handover means previous traffic is visible
  3. GPU memory in use     -- memory already allocated before you ran anything
  4. power at 0% util      -- a card already above idle means a live context remains
  5. stray GPU processes   -- compute processes that are not yours
  6. ECC error counters    -- volatile counts survive if the driver was not reloaded
  7. machine identity      -- host, driver, VBIOS, GPU UUIDs, so repeat rentals of
                              the same machine are not counted as new samples

BOUNDARY, deliberate: leftovers are recorded by PATH, SIZE, OWNER and TIME only.
This script never opens, reads, copies or hashes another tenant's file contents.
The metadata proves the leak; reading the data would be the thing we are
reporting. Do not change that.

Usage:  python3 handover_capture.py [--out handover_<host>_<time>.json]
"""
import argparse
import getpass
import json
import os
import platform
import pwd
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

SHARED_PATHS = ["/tmp", "/dev/shm", "/var/tmp", "/workspace", "/root", "/home", "/data", "/scratch"]
NVSMI_FIELDS = ("index,uuid,name,driver_version,vbios_version,memory.used,memory.total,"
                "utilization.gpu,power.draw,temperature.gpu,clocks.sm,clocks.mem,"
                "ecc.errors.corrected.volatile.total,ecc.errors.uncorrected.volatile.total,"
                "persistence_mode,compute_mode")


def run(cmd, timeout=25):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return 127, "", "not found: %s" % cmd[0]
    except Exception as e:
        return 1, "", str(e)


def owner(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def leftovers(limit=400):
    """Files owned by a DIFFERENT uid in shared paths. Metadata only -- never contents."""
    me, out, scanned = os.getuid(), [], 0
    for base in SHARED_PATHS:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base, topdown=True, onerror=lambda e: None):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            if root.count(os.sep) > base.count(os.sep) + 4:
                dirs[:] = []
            for fn in files:
                p = os.path.join(root, fn)
                scanned += 1
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if st.st_uid == me or st.st_uid == 0:
                    continue
                age_d = (time.time() - st.st_mtime) / 86400.0
                out.append({"path": p, "bytes": st.st_size, "uid": st.st_uid,
                            "owner": owner(st.st_uid),
                            "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                            "age_days": round(age_d, 1),
                            # old files in a home dir are almost always the image's own
                            # defaults (.bashrc and friends), not a previous tenant's work
                            "likely_image_default": age_d > 180,
                            "mode": oct(st.st_mode & 0o777)})
                if len(out) >= limit:
                    return out, scanned, True
    return out, scanned, False


def nvlink():
    rc, out, err = run(["nvidia-smi", "nvlink", "--getthroughput", "d"])
    if rc != 0:
        rc, out, err = run(["nvidia-smi", "nvlink", "-gt", "d"])
    total, links = 0.0, 0
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and "KiB" in parts[-1]:
            try:
                total += float(parts[-1].replace("KiB", "").strip())
                links += 1
            except ValueError:
                pass
    return {"available": rc == 0 and links > 0, "links_seen": links,
            "total_counter_kib": total, "raw": out[:4000], "error": err[:200]}


def gpus():
    rc, out, err = run(["nvidia-smi", "--query-gpu=" + NVSMI_FIELDS, "--format=csv,noheader"])
    rows = []
    if rc == 0:
        keys = NVSMI_FIELDS.split(",")
        for line in out.splitlines():
            vals = [v.strip() for v in line.split(",")]
            if len(vals) == len(keys):
                rows.append(dict(zip(keys, vals)))
    return rows, err[:200]


def procs():
    rc, out, _ = run(["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory",
                      "--format=csv,noheader"])
    mine = str(os.getpid())
    rows = []
    for line in (out.splitlines() if rc == 0 else []):
        v = [x.strip() for x in line.split(",")]
        if len(v) >= 3 and v[0] != mine:
            rows.append({"pid": v[0], "name": v[1], "used_memory": v[2]})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    a = ap.parse_args()
    t0 = time.time()
    print("HANDOVER CAPTURE -- do not run any workload before this finishes")
    g, gerr = gpus()
    nv = nvlink()
    p = procs()
    lo, scanned, capped = leftovers()
    rc_host, uptime, _ = run(["cat", "/proc/uptime"])
    snap = {
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "uid": os.getuid(),
        "kernel": platform.release(),
        "uptime_s": float(uptime.split()[0]) if rc_host == 0 and uptime else None,
        "gpus": g,
        "gpu_query_error": gerr,
        "nvlink": nv,
        "foreign_gpu_processes": p,
        "leftovers": {"count": len(lo), "files_scanned": scanned, "capped": capped, "files": lo},
        "capture_seconds": round(time.time() - t0, 1),
        "note": ("Leftovers recorded as metadata only -- contents never opened or hashed. "
                 "Run before any workload; afterwards the state is your own."),
    }
    name = a.out or "handover_%s_%s.json" % (snap["host"], datetime.now().strftime("%Y%m%d_%H%M%S"))
    with open(name, "w") as fh:
        json.dump(snap, fh, indent=2)

    print("\n--- WHAT THE PREVIOUS TENANT LEFT BEHIND ---")
    print("machine      : %s, kernel %s, up %.0f s" % (snap["host"], snap["kernel"], snap["uptime_s"] or 0))
    for x in g:
        print("GPU %s %s  driver %s  vbios %s" % (x.get("index"), x.get("name"),
                                                  x.get("driver_version"), x.get("vbios_version")))
        print("    memory in use at handover : %s of %s" % (x.get("memory.used"), x.get("memory.total")))
        print("    power / util / temp       : %s / %s / %s" % (x.get("power.draw"),
                                                                x.get("utilization.gpu"), x.get("temperature.gpu")))
        print("    volatile ECC (corr/uncorr): %s / %s" % (x.get("ecc.errors.corrected.volatile.total"),
                                                           x.get("ecc.errors.uncorrected.volatile.total")))
    print("NVLink counters at handover: %s" % (
        ("%.0f KiB total across %d links -- NOT zero, previous traffic is visible"
         % (nv["total_counter_kib"], nv["links_seen"])) if nv["available"] and nv["total_counter_kib"] > 0
        else ("zero" if nv["available"] else "no NVLink / unavailable")))
    print("GPU processes that are not mine: %d %s" % (len(p), p if p else ""))
    fresh = [f for f in lo if not f["likely_image_default"]]
    print("Files owned by another uid     : %d (of %d scanned%s)" % (len(lo), scanned, ", capped" if capped else ""))
    print("  of those, RECENT (not image defaults): %d  <-- this is the finding" % len(fresh))
    for f in (fresh or lo)[:10]:
        print("    %s  %d bytes  owner %s  %.1f days old%s" % (f["path"], f["bytes"], f["owner"],
              f["age_days"], "  [likely image default]" if f["likely_image_default"] else ""))
    if len(fresh or lo) > 10:
        print("    ... %d more in the json" % (len(fresh or lo) - 10))
    print("\nwritten: %s   (%.1f s)" % (name, snap["capture_seconds"]))
    print("Copy this file off the pod before you release it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
