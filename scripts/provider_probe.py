#!/usr/bin/env python3
"""
Watchdog provider benchmark -- probe suite. Run on YOUR OWN rented instance.

Runs the probes that don't need a second GPU or a workload:
  HH-02 VRAM Zeroed at Handover      HS-01 Kernel vs KEV
  HH-03 GPU Counter Reset            HS-02 Container Escape Surface
  HH-04 Live Context at Handover     HS-03 Namespace Isolation
  HH-05 GPU Reset Available          HS-04 Baked-in Credentials
                                     HS-05 Cloud Metadata Reachable
  BH-03 GPU Generation as Advertised

HH-01 (leftover files) is handover_capture.py. BH-01/BH-02 come from the ghost
suite, BH-04 and the 2-GPU tests from nvlink_units_test.py -- their results drop
into the same scoreboard by test_id.

RUN THIS BEFORE ANY WORKLOAD. Several checks only mean something at handover.

BOUNDARY: every probe reads only your own instance. HH-02 allocates and reads
YOUR OWN buffer. Nothing reaches into another tenant's memory, files or traffic.

Usage:  python3 provider_probe.py --provider vastai --advertised H200 [--out FILE]
"""
import argparse
import glob
import json
import os
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from wd_benchmark_tests import make_result, TESTS, GROUP_ORDER  # noqa: E402


def sh(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return 127, "", "not found: %s" % (cmd[0] if isinstance(cmd, list) else cmd)
    except Exception as e:
        return 1, "", str(e)


# ---- HH-02 VRAM zeroed at handover -------------------------------------------
def hh02_vram_zeroed():
    try:
        import torch
    except ImportError:
        return make_result("HH-02", "ERROR", "torch not installed; cannot allocate a GPU buffer")
    if not torch.cuda.is_available():
        return make_result("HH-02", "ERROR", "no CUDA GPU visible")
    # Allocate a large buffer WITHOUT initialising it and inspect the raw bytes.
    # Reading our own fresh allocation only. Zeroed => provider clears VRAM.
    try:
        n = 512 * 1024 * 1024
        buf = torch.empty(n, dtype=torch.uint8, device="cuda:0")
        import torch as _t
        chunks = 16
        step = n // chunks
        nonzero = 0
        sample = []
        for c in range(chunks):
            part = buf[c * step:(c + 1) * step]
            nz = int(_t.count_nonzero(part).item())
            nonzero += nz
            if nz and len(sample) < 3:
                idx = int(_t.nonzero(part)[0].item())
                sample.append({"offset": c * step + idx, "value": int(part[idx].item())})
        del buf
        _t.cuda.empty_cache()
        frac = nonzero / n
        if nonzero == 0:
            return make_result("HH-02", "PASS", "512 MB fresh allocation read back entirely zero",
                               bytes_checked=n, nonzero_bytes=0)
        # Non-zero can be prior tenant data OR driver scratch. State it honestly.
        return make_result("HH-02", "FAIL",
                           "fresh 512 MB allocation contained %d non-zero bytes (%.4f%%) -- VRAM not "
                           "zeroed at handover; source (previous tenant vs driver scratch) not "
                           "determinable without reading contents, which we do not do"
                           % (nonzero, frac * 100),
                           bytes_checked=n, nonzero_bytes=nonzero, sample_positions=sample)
    except Exception as e:
        return make_result("HH-02", "ERROR", "allocation/read failed: %s" % e)


# ---- HH-03 GPU counter reset -------------------------------------------------
def hh03_counters():
    fields = "ecc.errors.corrected.volatile.total,ecc.errors.uncorrected.volatile.total,pcie.replay.counter"
    rc, out, err = sh(["nvidia-smi", "--query-gpu=" + fields, "--format=csv,noheader,nounits"])
    nvrc, nvout, _ = sh(["nvidia-smi", "nvlink", "--getthroughput", "d"])
    nv_total = 0.0
    for line in nvout.splitlines():
        if "KiB" in line:
            try:
                nv_total += float(line.split(":")[-1].replace("KiB", "").strip())
            except ValueError:
                pass
    if rc != 0:
        return make_result("HH-03", "ERROR", "nvidia-smi query failed: %s" % err)
    rows, hot = [], []
    for line in out.splitlines():
        v = [x.strip() for x in line.split(",")]
        rows.append(v)
        for name, val in zip(fields.split(","), v):
            try:
                if float(val) > 0:
                    hot.append("%s=%s" % (name, val))
            except ValueError:
                pass
    if nv_total > 0:
        hot.append("nvlink_total=%.0f KiB" % nv_total)
    if not hot:
        return make_result("HH-03", "PASS", "ECC / PCIe replay / NVLink counters all zero at handover",
                           rows=rows, nvlink_total_kib=nv_total)
    return make_result("HH-03", "FAIL",
                       "counters non-zero at handover (previous tenant's activity visible): " + ", ".join(hot),
                       rows=rows, nvlink_total_kib=nv_total, nonzero=hot)


# ---- HH-04 live context at handover ------------------------------------------
def hh04_live_context():
    rc, out, err = sh(["nvidia-smi",
                       "--query-gpu=memory.used,utilization.gpu,power.draw,clocks.sm,clocks.max.sm",
                       "--format=csv,noheader,nounits"])
    if rc != 0:
        return make_result("HH-04", "ERROR", "nvidia-smi query failed: %s" % err)
    _, apps, _ = sh(["nvidia-smi", "--query-compute-apps=pid,used_memory", "--format=csv,noheader"])
    flags, rows = [], []
    for line in out.splitlines():
        v = [x.strip() for x in line.split(",")]
        rows.append(v)
        try:
            mem, util, power = float(v[0]), float(v[1]), float(v[2])
            if mem > 200:
                flags.append("memory.used=%.0fMB" % mem)
            if util > 0:
                flags.append("util=%.0f%%" % util)
        except (ValueError, IndexError):
            pass
    if apps.strip():
        flags.append("compute apps present: %s" % apps.replace("\n", "; "))
    if not flags:
        return make_result("HH-04", "PASS", "GPU at idle with no memory in use and no compute apps", rows=rows)
    return make_result("HH-04", "FAIL",
                       "GPU not clean at handover -- a previous context may still be resident: " + ", ".join(flags),
                       rows=rows)


# ---- HH-05 GPU reset available ----------------------------------------------
def hh05_gpu_reset():
    # Do NOT run --gpu-reset unattended: it fails if any process holds the GPU
    # and can disrupt a live workload. Probe permission by asking for help output
    # and by reading whether the operation is permitted, then report intent.
    rc, out, err = sh(["nvidia-smi", "--help"])
    supported = "--gpu-reset" in out or "-r," in out or "--gpu-reset" in err
    # A dry permission signal: try a reset with an obviously invalid index; a
    # permission error comes back differently from "invalid index".
    trc, tout, terr = sh(["nvidia-smi", "--gpu-reset", "-i", "999"])
    blob = (tout + " " + terr).lower()
    if "permission" in blob or "root" in blob or "privile" in blob:
        return make_result("HH-05", "BLOCKED",
                           "GPU reset requires privileges this rented container does not grant "
                           "(so the VRAM accounting gap cannot be cleared here): " + (terr or tout)[:160],
                           supported=supported)
    if not supported:
        return make_result("HH-05", "BLOCKED", "nvidia-smi build does not expose --gpu-reset")
    return make_result("HH-05", "PASS",
                       "GPU reset appears permitted (invalid-index probe returned no permission error). "
                       "Confirm for real, attended, on an idle GPU: nvidia-smi --gpu-reset -i 0",
                       probe_output=(terr or tout)[:160], supported=supported)


# ---- HS-01 kernel vs KEV -----------------------------------------------------
# A small, dated slice of CISA KEV Linux-kernel LPEs. Update from the live feed
# when online; a hit is a real finding, a miss is "none in this slice".
KEV_KERNEL = [
    ("CVE-2026-31431", "Copy Fail AF_ALG LPE", "disclosed 2026-04-29, in CISA KEV"),
    ("CVE-2024-1086", "nf_tables use-after-free LPE", "in CISA KEV"),
    ("CVE-2023-32233", "netfilter nf_tables LPE", "in CISA KEV"),
    ("CVE-2022-0847", "Dirty Pipe", "in CISA KEV"),
    ("CVE-2021-4034", "PwnKit (polkit)", "in CISA KEV"),
]


def hs01_kernel():
    rc, uname, _ = sh(["uname", "-rv"])
    if rc != 0:
        return make_result("HS-01", "ERROR", "uname failed")
    rc2, lsb, _ = sh(["cat", "/etc/os-release"])
    note = ("Version-string matching only: distributions backport fixes without changing the "
            "version, so this flags machines to check by hand, it does not prove exploitability.")
    return make_result("HS-01", "BLOCKED",
                       "running kernel: %s. Compare against CISA KEV kernel LPEs by hand or with a live "
                       "feed. %s" % (uname, note),
                       kernel=uname, os_release=lsb[:400], kev_slice=[c[0] for c in KEV_KERNEL])


# ---- HS-02 container escape surface -----------------------------------------
def hs02_escape():
    hits = []
    for sock in ("/var/run/docker.sock", "/run/docker.sock"):
        if os.path.exists(sock):
            hits.append("docker socket exposed: %s" % sock)
    rc, caps, _ = sh(["cat", "/proc/self/status"])
    capeff = ""
    for line in caps.splitlines():
        if line.startswith("CapEff:"):
            capeff = line.split()[1]
    # CapEff 0x...ffffffff-ish means near-full capabilities => privileged-ish
    dangerous_full = capeff and int(capeff, 16) & 0x3FFFFFFFFF == 0x3FFFFFFFFF
    if dangerous_full:
        hits.append("near-full Linux capabilities (CapEff=%s) -- privileged container" % capeff)
    rc, mounts, _ = sh(["cat", "/proc/mounts"])
    for risky in (" /host ", " /rootfs "):
        if risky in " " + mounts:
            hits.append("host path mounted:" + risky.strip())
    if "/dev/kmsg" in mounts or " /sys/firmware " in mounts:
        hits.append("host firmware/kernel-log paths mounted")
    if not hits:
        return make_result("HS-02", "PASS", "no docker socket, no near-full capabilities, no host mounts seen",
                           cap_eff=capeff)
    return make_result("HS-02", "FAIL", "container-escape surface present: " + "; ".join(hits), cap_eff=capeff)


# ---- HS-03 namespace isolation ----------------------------------------------
def hs03_namespaces():
    rc, out, _ = sh(["ps", "-e", "--no-headers"])
    nproc = len([l for l in out.splitlines() if l.strip()]) if rc == 0 else -1
    # In a well-isolated container you see only your own handful of processes.
    foreign_names = []
    for l in out.splitlines():
        if any(k in l for k in ("dockerd", "containerd", "kubelet", "sshd: root@")):
            foreign_names.append(l.strip()[:60])
    host_net = os.path.exists("/proc/1/net") and rc == 0
    hits = []
    if nproc > 80:
        hits.append("%d processes visible (host PID namespace not isolated?)" % nproc)
    if foreign_names:
        hits.append("host/daemon processes visible: %s" % foreign_names[:3])
    if not hits:
        return make_result("HS-03", "PASS", "process view looks contained (%d processes, no host daemons)" % nproc,
                           process_count=nproc)
    return make_result("HS-03", "FAIL", "namespace bleed: " + "; ".join(hits), process_count=nproc)


# ---- HS-04 baked-in credentials ---------------------------------------------
def hs04_creds():
    hits = []
    candidates = ["/root/.ssh/id_rsa", "/root/.ssh/id_ed25519", "/root/.aws/credentials",
                  "/root/.config/gcloud/credentials.db", "/root/.netrc", "/root/.git-credentials",
                  "/root/.docker/config.json"]
    for p in candidates:
        if os.path.isfile(p):
            try:
                sz = os.path.getsize(p)
            except OSError:
                sz = -1
            hits.append("%s (%d bytes)" % (p, sz))  # existence + size only, never contents
    # env vars that look like secrets
    for k in os.environ:
        if re.search(r"(?i)key|secret|token|passw", k) and len(os.environ[k]) > 12:
            hits.append("env var %s set (looks secret-like)" % k)
    if not hits:
        return make_result("HS-04", "PASS", "no credential files or secret-like env vars in the base image")
    return make_result("HS-04", "FAIL", "credentials present in the handed-over image/env: " + "; ".join(hits[:8]))


# ---- HS-05 cloud metadata reachable -----------------------------------------
def hs05_metadata():
    # 169.254.169.254 is the cloud metadata IP. Reachable from a tenant container
    # is a well-known SSRF / credential-theft exposure.
    reachable = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        rc = s.connect_ex(("169.254.169.254", 80))
        s.close()
        reachable = (rc == 0)
    except Exception as e:
        return make_result("HS-05", "ERROR", "probe failed: %s" % e)
    if not reachable:
        return make_result("HS-05", "PASS", "cloud metadata endpoint 169.254.169.254:80 not reachable")
    return make_result("HS-05", "FAIL",
                       "cloud metadata endpoint 169.254.169.254:80 reachable from inside the instance "
                       "(SSRF / credential-exposure surface)")


# ---- BH-03 GPU generation as advertised -------------------------------------
def bh03_generation(advertised):
    rc, out, _ = sh(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"])
    if rc != 0:
        return make_result("BH-03", "ERROR", "nvidia-smi query failed")
    names = [l.strip() for l in out.splitlines() if l.strip()]
    if not advertised:
        return make_result("BH-03", "BLOCKED", "no --advertised value given; GPUs present: %s" % names,
                           gpus=names)
    adv = advertised.strip().upper()
    ok = all(adv in n.upper() for n in names)
    if ok:
        return make_result("BH-03", "PASS", "all GPUs match advertised '%s': %s" % (advertised, names), gpus=names)
    return make_result("BH-03", "FAIL",
                       "GPU(s) present do not all match advertised '%s': %s" % (advertised, names), gpus=names)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True, help="short tag, e.g. vastai, runpod, lambda")
    ap.add_argument("--advertised", default="", help="GPU generation the listing sold, e.g. H200")
    ap.add_argument("--out")
    a = ap.parse_args()

    probes = [hh02_vram_zeroed, hh03_counters, hh04_live_context, hh05_gpu_reset,
              hs01_kernel, hs02_escape, hs03_namespaces, hs04_creds, hs05_metadata,
              lambda: bh03_generation(a.advertised)]
    results = [p() for p in probes]

    rc, host, _ = sh(["hostname"])
    doc = {"provider": a.provider, "host": host, "advertised_gpu": a.advertised,
           "captured_utc": datetime.now(timezone.utc).isoformat(),
           "boundary": "own-instance only; no probe reads another tenant's memory, files or traffic",
           "results": results}
    name = a.out or "benchmark_%s_%s.json" % (a.provider, datetime.now().strftime("%Y%m%d_%H%M%S"))
    with open(name, "w") as fh:
        json.dump(doc, fh, indent=2)

    print("WATCHDOG PROVIDER BENCHMARK -- %s  (own-instance only)" % a.provider)
    by_group = {}
    for r in results:
        by_group.setdefault(r["group"], []).append(r)
    for g in GROUP_ORDER:
        if g not in by_group:
            continue
        print("\n%s" % g)
        for r in by_group[g]:
            print("  %-6s %-28s %-8s %s" % (r["test_id"], r["title"], r["verdict"], r["detail"][:88]))
    tally = {}
    for r in results:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    print("\nTally: " + ", ".join("%s %d" % (k, tally[k]) for k in sorted(tally)))
    print("written: %s   (copy off the pod before releasing it)" % name)
    print("FAIL = provider did the wrong thing. BLOCKED = platform prevented the check.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
