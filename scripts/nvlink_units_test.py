#!/usr/bin/env python3
"""
Watchdog -- NVLINK UNITS + CROSS-GPU RESIDUAL. Needs 2 GPUs (NVLink preferred).

TEST 8 -- what do the counters actually count?
  nvidia-smi labels NVLink throughput counters KiB. The 30 July B200 alert
  reported 61,542,977,904 "KB/s", ~34x more than a B200's entire NVLink
  bandwidth -- impossible as a rate, and commit 8ba9c69 traced it to comparing
  cumulative counters instead of computing a rate. What the counter's UNIT
  really is was never settled, and every threshold depends on it.
  Method: read counters, copy a KNOWN number of bytes GPU0 -> GPU1, read again.
  counted_units / bytes_moved tells us the unit: ~1/1024 = KiB, ~1 = bytes.
  Repeated at three sizes; a unit that holds across all three is the answer.

TEST 9 -- cross-GPU residual.
  A 528 MB residual once appeared on an idle GPU1 after GPU0 compute, inside a
  Serial Alice CVM, never reproduced on a plain rented pod. Method: record GPU1
  memory while it does nothing, run a large allocation + compute on GPU0 only,
  exit, then re-read GPU1.

Needs torch with CUDA. Run handover_capture.py FIRST -- this script changes the
machine's state.

Usage:  python3 nvlink_units_test.py [--sizes 256 1024 4096] [--out nvlink_units_result.json]
"""
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone


def sh(cmd, timeout=60):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def counters():
    """Total NVLink data counter across all links, per GPU index, in the units nvidia-smi prints."""
    rc, out, _ = sh(["nvidia-smi", "nvlink", "--getthroughput", "d"])
    if rc != 0:
        rc, out, _ = sh(["nvidia-smi", "nvlink", "-gt", "d"])
    per_gpu, cur = {}, None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("GPU "):
            try:
                cur = int(s.split()[1].rstrip(":"))
                per_gpu.setdefault(cur, 0.0)
            except (ValueError, IndexError):
                cur = None
        elif cur is not None and "KiB" in s:
            try:
                per_gpu[cur] += float(s.split(":")[-1].replace("KiB", "").strip())
            except ValueError:
                pass
    return per_gpu, out


def mem_used_mb(i):
    rc, out, _ = sh(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits", "-i", str(i)])
    try:
        return float(out.splitlines()[0])
    except (ValueError, IndexError):
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[256, 1024, 4096], help="MiB per copy")
    ap.add_argument("--out", default="nvlink_units_result.json")
    a = ap.parse_args()
    try:
        import torch
    except ImportError:
        print("torch not installed -- pip install torch, or use a pod image that has it"); return 2
    if not torch.cuda.is_available() or torch.cuda.device_count() < 2:
        print("needs 2 visible CUDA GPUs; saw %d" % (torch.cuda.device_count() if torch.cuda.is_available() else 0))
        return 2

    res = {"started_utc": datetime.now(timezone.utc).isoformat(),
           "gpu_count": torch.cuda.device_count(),
           "gpu0": torch.cuda.get_device_name(0), "gpu1": torch.cuda.get_device_name(1),
           "peer_access": None, "unit_trials": [], "cross_gpu_residual": {}}
    try:
        res["peer_access"] = bool(torch.cuda.can_device_access_peer(0, 1))
    except Exception as e:
        res["peer_access"] = "unknown: %s" % e
    print("GPUs: %s / %s   peer access: %s" % (res["gpu0"], res["gpu1"], res["peer_access"]))

    print("\nTEST 8 -- NVLink counter units")
    for mib in a.sizes:
        before, _ = counters()
        src = torch.empty(int(mib * 1024 * 1024 // 4), dtype=torch.float32, device="cuda:0")
        torch.cuda.synchronize(0)
        dst = src.to("cuda:1", non_blocking=False)
        torch.cuda.synchronize(1)
        del src, dst
        torch.cuda.empty_cache()
        time.sleep(2.0)                      # counters refresh on their own schedule
        after, _ = counters()
        moved = mib * 1024 * 1024
        delta = {g: after.get(g, 0) - before.get(g, 0) for g in set(before) | set(after)}
        tot = sum(v for v in delta.values() if v > 0)
        trial = {"copy_mib": mib, "bytes_moved": moved, "counter_delta_per_gpu": delta,
                 "counter_delta_total": tot,
                 "units_per_byte": (tot / moved) if moved else None,
                 "reads_as": None}
        if tot > 0:
            r = tot / moved
            trial["reads_as"] = ("KiB (counter ~ bytes/1024)" if 0.0004 < r < 0.002 else
                                 "bytes (counter ~ bytes)" if 0.4 < r < 2.5 else
                                 "neither -- %.3g units per byte" % r)
        print("  %5d MiB copied -> counter moved %.0f  (%s)" % (mib, tot, trial["reads_as"] or "no change"))
        res["unit_trials"].append(trial)

    print("\nTEST 9 -- cross-GPU residual (GPU1 idle throughout)")
    g1_before = mem_used_mb(1)
    big = torch.empty(int(2 * 1024 * 1024 * 1024 // 4), dtype=torch.float32, device="cuda:0")
    for _ in range(20):
        big = big * 1.000001
    torch.cuda.synchronize(0)
    g1_during = mem_used_mb(1)
    del big
    torch.cuda.empty_cache()
    torch.cuda.synchronize(0)
    time.sleep(3)
    g1_after = mem_used_mb(1)
    res["cross_gpu_residual"] = {"gpu1_mb_before": g1_before, "gpu1_mb_during_gpu0_work": g1_during,
                                 "gpu1_mb_after": g1_after,
                                 "increase_mb": None if None in (g1_before, g1_after) else round(g1_after - g1_before, 1)}
    print("  GPU1 memory: before %.0f MB, during GPU0 work %.0f MB, after %.0f MB"
          % (g1_before or 0, g1_during or 0, g1_after or 0))
    inc = res["cross_gpu_residual"]["increase_mb"]
    print("  -> %s" % ("GPU1 gained %.0f MB from GPU0's work -- reproduce and record" % inc
                       if inc and inc > 50 else "no cross-GPU residual seen in this run"))

    res["finished_utc"] = datetime.now(timezone.utc).isoformat()
    with open(a.out, "w") as fh:
        json.dump(res, fh, indent=2)
    print("\nwritten: %s" % a.out)
    print("Units verdict stands only if all three sizes agree. One trial is not a result.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
