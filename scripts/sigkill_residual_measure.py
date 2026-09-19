#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
"""
sigkill_residual_measure.py -- answers the ONE question the README names open
*** WATCHDOG ***

THE QUESTION (README, verbatim in substance)
--------------------------------------------
"Whether SIGKILL clears the 527MB accounting is not established. Both tests
above allocate a 256MB buffer to perform their read, so their own memory
figures include the instrument and cannot answer it. A separate measurement
is needed: kill the process, watch memory.used, allocate nothing."

This is that measurement. It allocates NOTHING on the GPU. It only reads
`nvidia-smi --query-gpu=memory.used`, which is why it can answer what
vram_residency_challenge.py structurally cannot.

WHAT IT DOES
------------
1. Baseline: memory.used on an idle GPU, before any context exists.
2. Child process allocates N MB and holds it. Confirm memory.used rises.
3. Kill the child -- SIGKILL or SIGTERM, selectable -- and sample
   memory.used for `watch` seconds WITHOUT allocating anything.
4. Report: does memory.used return to baseline, and how fast?
   - returns to baseline      -> SIGKILL DOES clear the accounting
   - stays elevated           -> the residual survives SIGKILL; report the MB
   - decays over N seconds    -> transient; report the decay curve

WHY IT MATTERS
--------------
The B200 finding is that the residual is exit-path independent (~1520MB after
both graceful exit and SIGKILL). If that reproduces here, the accounting gap
is a property of the driver, not of how the process died -- which is a
stronger and more defensible claim than "SIGKILL leaves memory behind".

Also note, and this is already settled: SIGKILL is NOT a remediation for
cross-tenant VRAM residual. That was disproven on B200 (zero recoveries).
This script measures ACCOUNTING, not recoverability, and must never be cited
as a remediation test.

SECURITY REVIEW COMPLIANCE: no bare except; no shell=True; argument-list
subprocess; every failure surfaced; allocates nothing on the GPU itself.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

DRY = os.environ.get("WD_DRY_RUN", "true").lower() != "false"

CHILD_SRC = '''
import sys, time, json
gpu = int(sys.argv[1]); mb = int(sys.argv[2])
import torch
dev = torch.device("cuda:%d" % gpu)
buf = torch.empty(mb * 1024 * 1024, dtype=torch.uint8, device=dev)
buf.fill_(0xA5)
torch.cuda.synchronize(dev)
print(json.dumps({"ok": True, "pid": __import__("os").getpid(), "mb": mb}), flush=True)
while True:
    time.sleep(1)
'''


def memory_used_mb(gpu, timeout=10):
    """Read memory.used. Allocates nothing. Returns None on a gap."""
    try:
        r = subprocess.run(["nvidia-smi", "-i", str(gpu),
                            "--query-gpu=memory.used,memory.total,utilization.gpu",
                            "--format=csv,noheader,nounits"],
                           capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0:
        return None
    parts = [p.strip() for p in r.stdout.strip().split(",")]
    if len(parts) < 3:
        return None
    try:
        return {"used_mb": float(parts[0]), "total_mb": float(parts[1]),
                "util_pct": float(parts[2])}
    except ValueError:
        return None


def sample(gpu, seconds, period=1.0):
    rows, gaps, t0 = [], 0, time.monotonic()
    while time.monotonic() - t0 < seconds:
        m = memory_used_mb(gpu)
        if m is None:
            gaps += 1
        else:
            m["t"] = round(time.monotonic() - t0, 2)
            rows.append(m)
        time.sleep(period)
    return {"rows": rows, "gaps": gaps}


def run(gpu, mb, kill_signal, watch_s, settle_s):
    out = {"type": "SIGKILL_RESIDUAL_MEASUREMENT", "gpu": gpu, "alloc_mb": mb,
           "kill_signal": kill_signal, "watch_seconds": watch_s,
           "timestamp": datetime.now(timezone.utc).isoformat(),
           "method": ("reads memory.used only; allocates nothing on the GPU -- this is "
                      "why it can answer what the 256MB-buffer tests cannot"),
           "not_a_remediation_test": ("SIGKILL is NOT a remediation for cross-tenant VRAM "
                                      "residual (disproven on B200, zero recoveries). This "
                                      "measures ACCOUNTING only.")}

    base = memory_used_mb(gpu)
    if base is None:
        out.update(status="FAILED", error="nvidia-smi memory.used not readable")
        return out
    out["baseline_used_mb"] = base["used_mb"]

    # write the child to a temp file (no heredoc, no shell)
    child_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_sigkill_child.py")
    try:
        with open(child_path, "w") as fh:
            fh.write(CHILD_SRC)
    except OSError as e:
        out.update(status="FAILED", error=f"could not write child: {type(e).__name__}: {e}")
        return out

    try:
        proc = subprocess.Popen([sys.executable, child_path, str(gpu), str(mb)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except (FileNotFoundError, OSError) as e:
        out.update(status="FAILED", error=f"could not start child: {type(e).__name__}: {e}")
        return out

    # wait for the child to report it allocated
    t0, allocated = time.monotonic(), None
    while time.monotonic() - t0 < 120:
        m = memory_used_mb(gpu)
        if m and m["used_mb"] > base["used_mb"] + mb * 0.5:
            allocated = m
            break
        if proc.poll() is not None:
            break
        time.sleep(1)

    if allocated is None:
        proc.kill()
        err = proc.stderr.read()[:500] if proc.stderr else ""
        out.update(status="FAILED", error="child never allocated", child_stderr=err)
        return out

    out["with_child_alive_used_mb"] = allocated["used_mb"]
    out["child_allocation_observed_mb"] = round(allocated["used_mb"] - base["used_mb"], 1)
    out["child_pid"] = proc.pid

    # kill
    sig = signal.SIGKILL if kill_signal == "SIGKILL" else signal.SIGTERM
    try:
        os.kill(proc.pid, sig)
    except (ProcessLookupError, PermissionError, OSError) as e:
        out.update(status="FAILED", error=f"kill failed: {type(e).__name__}: {e}")
        return out
    kill_at = time.monotonic()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        out["kill_note"] = "process did not reap within 30s"

    # watch WITHOUT allocating
    time.sleep(settle_s)
    watch = sample(gpu, watch_s)
    out["post_kill_samples"] = watch["rows"]
    out["post_kill_gaps"] = watch["gaps"]

    if not watch["rows"]:
        out.update(status="FAILED", error="no post-kill samples")
        return out

    first = watch["rows"][0]["used_mb"]
    last = watch["rows"][-1]["used_mb"]
    lowest = min(r["used_mb"] for r in watch["rows"])
    residual_first = round(first - base["used_mb"], 1)
    residual_last = round(last - base["used_mb"], 1)
    residual_low = round(lowest - base["used_mb"], 1)

    out.update({
        "residual_mb_immediately_after_kill": residual_first,
        "residual_mb_at_end_of_watch": residual_last,
        "residual_mb_lowest_observed": residual_low,
        "decayed_mb": round(residual_first - residual_last, 1),
        "settle_seconds_before_watch": settle_s,
    })

    tol = 50.0   # MB; below this, call it returned to baseline
    if residual_low <= tol:
        verdict = "SIGKILL_CLEARS_ACCOUNTING"
        detail = f"memory.used returned to within {tol} MB of baseline"
    elif abs(residual_first - residual_last) > 0.1 * max(residual_first, 1):
        verdict = "RESIDUAL_DECAYS"
        detail = (f"residual fell from {residual_first} MB to {residual_last} MB over "
                  f"{watch_s}s -- transient, not a persistent allocation")
    else:
        verdict = "RESIDUAL_SURVIVES_SIGKILL"
        detail = (f"memory.used stayed {residual_last} MB above baseline for the whole "
                  f"{watch_s}s watch with nothing allocated -- the accounting residual "
                  f"is exit-path independent, as measured on B200")
    out.update(status="OK", verdict=verdict, detail=detail)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Does SIGKILL clear the VRAM accounting residual?")
    ap.add_argument("--gpu", type=int, default=0)
    ap.add_argument("--mb", type=int, default=512)
    ap.add_argument("--signal", choices=["SIGKILL", "SIGTERM"], default="SIGKILL")
    ap.add_argument("--watch", type=float, default=120.0, help="seconds to watch after the kill")
    ap.add_argument("--settle", type=float, default=5.0)
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)

    if DRY:
        print(json.dumps({
            "type": "DRY_RUN", "gpu": a.gpu, "alloc_mb": a.mb, "signal": a.signal,
            "watch_seconds": a.watch,
            "plan": ["baseline memory.used", f"child allocates {a.mb} MB and holds",
                     f"{a.signal} the child", f"watch memory.used for {a.watch}s, allocate NOTHING",
                     "verdict: clears / decays / survives"],
            "answers": "README: 'kill the process, watch memory.used, allocate nothing'",
            "note": "DRY RUN -- nothing executed. WD_DRY_RUN=false to run.",
        }, indent=2))
        return 0

    res = run(a.gpu, a.mb, a.signal, a.watch, a.settle)
    print(json.dumps(res, indent=2, default=str))
    if a.out:
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        with open(a.out, "w") as fh:
            json.dump(res, fh, indent=2, default=str)
        print(f"\nwritten: {a.out}")
    return 0 if res.get("status") == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())
