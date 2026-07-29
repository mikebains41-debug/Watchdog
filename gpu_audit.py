#!/usr/bin/env python3
"""
gpu_audit.py -- Watchdog run-on-demand audit for a single rented GPU instance.

Three checks, each producing a result you can defend if someone re-runs it:

  1. contention   -- measured throughput loss under a noisy neighbour.
                     Runs the benchmark N times (default 3) and reports every
                     run plus mean and spread, so it is never a single reading.
  2. tenant_files -- leftover files from a prior tenant in shared temp dirs.
                     Files are COUNTED and their age/size recorded. Contents
                     are NEVER opened. The record says so explicitly.
  3. stale_cve    -- running kernel version checked against known CVEs.
                     Version check only; nothing is exploited. Affected-version
                     matching is only done when you supply authoritative ranges
                     (--cve-db), because guessing ranges would be fabrication.

Any check that cannot run (no GPU, no torch, no permission) reports NOT_RUN
with a reason instead of crashing or inventing a result.

Output: one JSON record per run (merge many with aggregate_audits.py for the
multi-provider table) plus a printed summary.

Usage:
  python3 gpu_audit.py --provider vast.ai --gpu H200
  python3 gpu_audit.py --only tenant_files,stale_cve      # skip the GPU test
  python3 gpu_audit.py --runs 5 --window 10 --competitors 2
"""
import argparse, json, os, subprocess, sys, tempfile, time, statistics
from datetime import datetime, timezone

NOT_RUN = "NOT_RUN"


# ----------------------------------------------------------------------------
# 1. Contention
# ----------------------------------------------------------------------------
def _gpu_ready():
    try:
        import torch
        return bool(torch.cuda.is_available())
    except Exception:
        return False


def _measure_iters(window_s, size):
    """Fixed-size matmul loop; returns iterations/second over the window."""
    import torch
    a = torch.randn(size, size, device="cuda")
    b = torch.randn(size, size, device="cuda")
    torch.cuda.synchronize()
    n = 0
    t0 = time.time()
    while time.time() - t0 < window_s:
        _ = a @ b
        torch.cuda.synchronize()
        n += 1
    return n / (time.time() - t0)


_COMPETITOR_SRC = """
import torch, time
a = torch.randn(4096, 4096, device="cuda")
b = torch.randn(4096, 4096, device="cuda")
torch.cuda.synchronize()
while True:
    _ = a @ b
    torch.cuda.synchronize()
"""


def _spawn_competitors(count):
    fd, path = tempfile.mkstemp(suffix="_competitor.py")
    with os.fdopen(fd, "w") as f:
        f.write(_COMPETITOR_SRC)
    procs = [subprocess.Popen([sys.executable, path],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
             for _ in range(count)]
    return procs, path


def _stop(procs, path):
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()
    try:
        os.remove(path)
    except OSError:
        pass


def contention_check(runs, window, competitors, size):
    if not _gpu_ready():
        return {"status": NOT_RUN,
                "reason": "torch+CUDA GPU not available on this host"}
    per_run = []
    for _ in range(runs):
        baseline = _measure_iters(window, size)
        procs, path = _spawn_competitors(competitors)
        time.sleep(1.0)  # let competitors ramp
        contended = _measure_iters(window, size)
        _stop(procs, path)
        deg = round((baseline - contended) / baseline * 100, 2) if baseline else None
        per_run.append({"baseline_iters_s": round(baseline, 2),
                        "contended_iters_s": round(contended, 2),
                        "degradation_pct": deg})
    degs = [r["degradation_pct"] for r in per_run if r["degradation_pct"] is not None]
    mean = round(statistics.mean(degs), 2) if degs else None
    spread = round(statistics.pstdev(degs), 2) if len(degs) > 1 else 0.0
    return {"status": "OK",
            "runs": per_run,
            "competitors": competitors,
            "mean_degradation_pct": mean,
            "stdev_pct": spread,
            "verdict": (f"measured {mean}% throughput loss under {competitors} "
                        f"noisy neighbour(s), +/- {spread}% across {runs} runs")
            if mean is not None else "inconclusive"}


# ----------------------------------------------------------------------------
# 2. Tenant files (count + age, never read)
# ----------------------------------------------------------------------------
SHARED_DIRS = ["/tmp", "/var/tmp", "/dev/shm"]


def tenant_files_check(min_age_hours, sample=10):
    me = os.getuid()
    now = time.time()
    cutoff = min_age_hours * 3600
    found, scanned_dirs, errors = [], [], []
    for base in SHARED_DIRS:
        if not os.path.isdir(base):
            continue
        scanned_dirs.append(base)
        for root, dirs, files in os.walk(base, topdown=True):
            for name in files:
                p = os.path.join(root, name)
                try:
                    st = os.lstat(p)  # lstat: never follows/opens
                except OSError:
                    continue
                if st.st_uid != me and (now - st.st_mtime) > cutoff:
                    found.append({"path": p, "uid": st.st_uid,
                                  "age_days": round((now - st.st_mtime) / 86400, 1),
                                  "size_bytes": st.st_size})
    found.sort(key=lambda x: x["age_days"], reverse=True)
    return {"status": "OK",
            "dirs_scanned": scanned_dirs,
            "contents_inspected": False,  # explicit and permanent
            "leftover_count": len(found),
            "oldest_age_days": found[0]["age_days"] if found else 0,
            "sample_paths_only": [f["path"] for f in found[:sample]],
            "verdict": (f"{len(found)} file(s) owned by another user found in "
                        f"shared temp, oldest {found[0]['age_days']}d -- contents "
                        f"NOT inspected") if found
                       else "no foreign-owned files in shared temp dirs"}


# ----------------------------------------------------------------------------
# 3. Stale CVE (version check only)
# ----------------------------------------------------------------------------
# Shipped references only. Affected-version ranges are intentionally absent:
# supply them via --cve-db (JSON list of {id,name,affected_min,affected_max,ref})
# so a match is based on authoritative data, not a guessed threshold.
KNOWN_CVES = [
    {"id": "CVE-2026-31431", "name": "Copy Fail",
     "ref": "CISA KEV", "note": "container-escape; kernel version fragile to backports"},
    {"id": "CVE-2026-64600", "name": "RefluXFS",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2026-64600",
     "note": "CVSS 7.8 HIGH, local-access-only"},
]


def _kernel():
    try:
        return subprocess.run(["uname", "-r"], capture_output=True, text=True,
                              timeout=5).stdout.strip()
    except Exception:
        return None


def _vtuple(s):
    out = []
    for part in s.split("."):
        num = ""
        for ch in part:
            if ch.isdigit():
                num += ch
            else:
                break
        if num:
            out.append(int(num))
    return tuple(out)


def stale_cve_check(cve_db_path):
    kernel = _kernel()
    if kernel is None:
        return {"status": NOT_RUN, "reason": "could not read `uname -r`"}
    if not cve_db_path:
        return {"status": "PARTIAL", "kernel": kernel,
                "range_match": "NOT_IMPLEMENTED (no authoritative --cve-db supplied)",
                "candidates_to_verify": KNOWN_CVES,
                "verdict": (f"kernel {kernel}; verify manually against the listed "
                            f"CVEs -- automated range match needs authoritative data")}
    with open(cve_db_path) as f:
        db = json.load(f)
    kv = _vtuple(kernel)
    hits = []
    for c in db:
        lo = _vtuple(c.get("affected_min", "0"))
        hi = _vtuple(c.get("affected_max", "0"))
        if lo <= kv <= hi:
            hits.append({"id": c["id"], "name": c.get("name"), "ref": c.get("ref")})
    return {"status": "OK", "kernel": kernel, "cve_db": cve_db_path,
            "matches": hits,
            "verdict": (f"kernel {kernel} matches {len(hits)} known CVE(s): "
                        + ", ".join(h["id"] for h in hits)) if hits
                       else f"kernel {kernel} matches no CVE in supplied db"}


# ----------------------------------------------------------------------------
# Driver
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Watchdog single-instance GPU audit")
    ap.add_argument("--provider", default="unknown")
    ap.add_argument("--gpu", default="unknown")
    ap.add_argument("--region", default="unknown")
    ap.add_argument("--only", default="", help="comma list: contention,tenant_files,stale_cve")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--window", type=int, default=8, help="seconds per measurement")
    ap.add_argument("--competitors", type=int, default=1)
    ap.add_argument("--matmul-size", type=int, default=4096)
    ap.add_argument("--min-age-hours", type=float, default=1.0)
    ap.add_argument("--cve-db", default="", help="JSON with authoritative affected ranges")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    only = {s.strip() for s in args.only.split(",") if s.strip()}
    run = lambda name: (not only) or (name in only)

    record = {
        "tool": "watchdog/gpu_audit.py",
        "schema": 1,
        "host": os.uname().nodename,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "provider": args.provider, "gpu": args.gpu, "region": args.region,
        "checks": {},
    }
    if run("contention"):
        record["checks"]["contention"] = contention_check(
            args.runs, args.window, args.competitors, args.matmul_size)
    if run("tenant_files"):
        record["checks"]["tenant_files"] = tenant_files_check(args.min_age_hours)
    if run("stale_cve"):
        record["checks"]["stale_cve"] = stale_cve_check(args.cve_db)

    out = args.out or f"audit_{record['host']}_{int(time.time())}.json"
    with open(out, "w") as f:
        json.dump(record, f, indent=2)

    print(f"\nWatchdog audit  |  {record['provider']}  {record['gpu']}  "
          f"{record['host']}  {record['timestamp_utc']}")
    print("-" * 72)
    for name, res in record["checks"].items():
        print(f"[{name}]  {res.get('status')}")
        print(f"    {res.get('verdict') or res.get('reason') or res}")
    print("-" * 72)
    print(f"record written: {out}\n")


if __name__ == "__main__":
    main()
