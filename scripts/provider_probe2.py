#!/usr/bin/env python3
"""
Watchdog provider benchmark -- probe suite round 2 (researched, cited).

Runs the new own-instance probes:
  HH-06 Host RAM Scrubbed            HS-06 Container Toolkit Version (NVIDIAScape)
  HH-07 Shared Memory / IPC Residue  HS-07 Metadata IMDS Version
  HH-08 GPU State at Handover        HS-08 Provider Agent Reachable
  HH-09 Disk & Log Residue           HS-09 VBIOS / Firmware Integrity
  HH-10 Network Trace Residue        HS-10 Network Egress Openness
  HH-11 GPU Local-Memory Residue     SC-01 Co-Tenant Side-Channel Exposure (config only)

RUN BEFORE ANY WORKLOAD. Results merge into the same scoreboard by test_id.

Two hard lines, enforced in code:
  - HS-07 detects which IMDS *version* is exposed. It NEVER requests the
    credential path (/.../iam/security-credentials). That path is the attack.
  - SC-01 only reads THIS machine's configuration. It never observes a neighbour.

Usage:  python3 provider_probe2.py --provider vastai [--expect-vbios STR] [--out FILE]
"""
import argparse
import glob
import json
import os
import re
import socket
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from wd_benchmark_tests import make_result  # noqa: E402
from wd_benchmark_tests_ext import EXT_TESTS, CITATIONS  # noqa: E402

# register the round-2 ids into the shared TESTS map so make_result accepts them
import wd_benchmark_tests as base  # noqa: E402
base.TESTS.update(EXT_TESTS)


def sh(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return 127, "", "not found: %s" % (cmd[0] if isinstance(cmd, list) else cmd)
    except Exception as e:
        return 1, "", str(e)


def cite(tid):
    return {"citations": CITATIONS.get(tid, [])}


# ---- HH-06 host RAM scrubbed -------------------------------------------------
def hh06_host_ram():
    # Allocate a chunk of host memory WITHOUT zeroing and inspect it. We use
    # ctypes.malloc (not calloc) so pages are not zero-filled by the allocator;
    # freshly faulted anonymous pages are zeroed by the kernel, so non-zero here
    # would indicate memory handed over without scrubbing. Own process only.
    import ctypes
    try:
        size = 256 * 1024 * 1024
        libc = ctypes.CDLL(None)
        libc.malloc.restype = ctypes.c_void_p
        p = libc.malloc(ctypes.c_size_t(size))
        if not p:
            return make_result("HH-06", "ERROR", "malloc failed", **cite("HH-06"))
        buf = (ctypes.c_ubyte * size).from_address(p)
        nonzero, sample, step = 0, [], 65536
        for off in range(0, size, step):
            b = buf[off]
            if b:
                nonzero += 1
                if len(sample) < 3:
                    sample.append(off)
        libc.free(ctypes.c_void_p(p))
        checked = size // step
        if nonzero == 0:
            return make_result("HH-06", "PASS",
                               "256 MB host allocation sampled every 64 KB -- all zero", samples=checked, **cite("HH-06"))
        return make_result("HH-06", "FAIL",
                           "host memory not zero at handover: %d of %d sampled 64KB pages non-zero "
                           "(source not read; contents never inspected)" % (nonzero, checked),
                           samples=checked, nonzero=nonzero, sample_offsets=sample, **cite("HH-06"))
    except Exception as e:
        return make_result("HH-06", "ERROR", "probe failed: %s" % e, **cite("HH-06"))


# ---- HH-07 shared memory / IPC residue --------------------------------------
def hh07_ipc():
    me = os.getuid()
    hits = []
    shm = []
    for base_dir in ("/dev/shm", "/run/shm"):
        if os.path.isdir(base_dir):
            for fn in os.listdir(base_dir):
                try:
                    st = os.lstat(os.path.join(base_dir, fn))
                    if st.st_uid != me and st.st_uid != 0:
                        shm.append("%s/%s (uid %d, %d bytes)" % (base_dir, fn, st.st_uid, st.st_size))
                except OSError:
                    pass
    rc, out, _ = sh(["ipcs", "-m"])   # shared memory segments
    seg_foreign = [l for l in out.splitlines() if l and l[0:1] == "0" and str(me) not in l][:5] if rc == 0 else []
    if shm:
        hits.append("foreign /dev/shm files: " + "; ".join(shm[:5]))
    if seg_foreign:
        hits.append("%d SysV shm segment(s) not owned by me" % len(seg_foreign))
    if not hits:
        return make_result("HH-07", "PASS", "no foreign /dev/shm files or SysV IPC segments")
    return make_result("HH-07", "FAIL", "IPC residue from a previous tenant: " + "; ".join(hits))


# ---- HH-08 GPU state at handover --------------------------------------------
def hh08_gpu_state():
    rc, out, err = sh(["nvidia-smi",
                       "--query-gpu=mig.mode.current,ecc.mode.current,persistence_mode,"
                       "clocks.applications.graphics,power.limit,power.default_limit",
                       "--format=csv,noheader"])
    if rc != 0:
        return make_result("HH-08", "ERROR", "nvidia-smi query failed: %s" % err)
    flags, rows = [], []
    for line in out.splitlines():
        v = [x.strip() for x in line.split(",")]
        rows.append(v)
        try:
            mig, ecc, pers, appclk, plim, pdef = v
            if mig.lower().startswith("enabled"):
                flags.append("MIG still enabled (previous tenant's partitioning)")
            if ecc.lower().startswith("disabled"):
                flags.append("ECC disabled -- error detection off")
            if appclk and appclk not in ("[N/A]", "0"):
                flags.append("application clock pinned at %s" % appclk)
            if plim and pdef and plim != pdef:
                flags.append("power limit %s != default %s" % (plim, pdef))
        except ValueError:
            pass
    if not flags:
        return make_result("HH-08", "PASS", "GPU in default state (no MIG, ECC on, no pinned clocks/power)", rows=rows)
    return make_result("HH-08", "FAIL", "GPU left in a non-default state at handover: " + "; ".join(flags), rows=rows)


# ---- HH-09 disk & log residue -----------------------------------------------
def hh09_disk_logs():
    me = os.getuid()
    hits = []
    for p in ("/root/.bash_history", "/root/.python_history", "/var/log/auth.log",
              "/var/log/wtmp", "/var/log/syslog"):
        if os.path.isfile(p) and os.access(p, os.R_OK):
            try:
                sz = os.path.getsize(p)
            except OSError:
                sz = -1
            if sz > 0:
                hits.append("%s readable (%d bytes)" % (p, sz))   # existence/size only
    # other users' home dirs present and readable
    if os.path.isdir("/home"):
        for h in os.listdir("/home"):
            hp = os.path.join("/home", h)
            try:
                if os.stat(hp).st_uid != me and os.access(hp, os.R_OK | os.X_OK):
                    hits.append("readable home dir /home/%s" % h)
            except OSError:
                pass
    if not hits:
        return make_result("HH-09", "PASS", "no readable prior-tenant history, logs, or home dirs")
    return make_result("HH-09", "FAIL", "disk/log residue readable at handover: " + "; ".join(hits[:8]))


# ---- HH-10 network trace residue --------------------------------------------
def hh10_net_trace():
    hits = []
    rc, arp, _ = sh(["cat", "/proc/net/arp"])
    arp_rows = [l for l in arp.splitlines()[1:] if l.strip() and "00:00:00:00:00:00" not in l] if rc == 0 else []
    if len(arp_rows) > 1:
        hits.append("%d populated ARP entries" % len(arp_rows))
    for p in ("/root/.ssh/known_hosts",):
        if os.path.isfile(p) and os.path.getsize(p) > 0:
            hits.append("%s present (%d bytes)" % (p, os.path.getsize(p)))
    for p in ("/etc/resolv.conf",):
        if os.path.isfile(p):
            rc2, txt, _ = sh(["grep", "-c", "nameserver", p])
            # resolv.conf is expected; only flag a systemd cache file if present
    if os.path.isfile("/var/cache/nscd/hosts"):
        hits.append("nscd host cache present")
    if not hits:
        return make_result("HH-10", "PASS", "no notable ARP/known_hosts/DNS-cache residue")
    return make_result("HH-10", "FAIL", "network-trace residue from a previous tenant: " + "; ".join(hits))


# ---- HH-11 GPU local-memory residue (LeftoverLocals class) -------------------
def hh11_leftoverlocals():
    # The true LeftoverLocals test reads uninitialised GPU *local/shared* memory
    # across kernels. A full test needs an OpenCL/CUDA kernel dumping __shared__.
    # torch can't allocate shared memory directly, so on NVIDIA (confirmed NOT
    # affected by CVE-2023-4969) we report the citation and mark it a targeted
    # follow-up rather than fake a result.
    try:
        import torch
        name = torch.cuda.get_device_name(0) if torch.cuda.is_available() else "no CUDA"
    except Exception:
        name = "torch unavailable"
    return make_result("HH-11", "BLOCKED",
                       "GPU local-memory dump needs a custom CUDA/OpenCL kernel (not expressible in torch). "
                       "NVIDIA was confirmed NOT affected by CVE-2023-4969; a dedicated kernel probe is the "
                       "real test. GPU seen: %s" % name, **cite("HH-11"))


# ---- HS-06 container toolkit version ----------------------------------------
def hs06_toolkit():
    ver = None
    for cmd in (["nvidia-container-cli", "--version"], ["nvidia-container-runtime", "--version"],
                ["nvidia-ctk", "--version"]):
        rc, out, err = sh(cmd)
        if rc == 0:
            m = re.search(r"(\d+\.\d+\.\d+)", out + " " + err)
            if m:
                ver = m.group(1); break
    if ver is None:
        return make_result("HS-06", "BLOCKED",
                           "NVIDIA Container Toolkit not found inside the container (may run on the host only)",
                           **cite("HS-06"))
    def tup(s):
        return tuple(int(x) for x in s.split("."))
    vulnerable = tup(ver) <= (1, 17, 7)
    if vulnerable:
        return make_result("HS-06", "FAIL",
                           "NVIDIA Container Toolkit %s <= 1.17.7 -- vulnerable to NVIDIAScape "
                           "CVE-2025-23266 (CVSS 9.0 container escape to host root)" % ver,
                           version=ver, **cite("HS-06"))
    return make_result("HS-06", "PASS", "NVIDIA Container Toolkit %s is past the NVIDIAScape patch line" % ver,
                       version=ver, **cite("HS-06"))


# ---- HS-07 metadata IMDS version (never touches credentials) -----------------
def hs07_imds():
    IP = "169.254.169.254"
    # reachable?
    try:
        s = socket.socket(); s.settimeout(2.0)
        reachable = s.connect_ex((IP, 80)) == 0
        s.close()
    except Exception as e:
        return make_result("HS-07", "ERROR", "probe failed: %s" % e, **cite("HS-07"))
    if not reachable:
        return make_result("HS-07", "PASS", "cloud metadata endpoint %s:80 not reachable" % IP, **cite("HS-07"))
    # Reachable. Determine version WITHOUT reading credentials.
    # IMDSv2 requires a PUT token for ANY data read. We probe the metadata ROOT
    # only -- never /iam/security-credentials.
    v1_open = False
    try:
        req = urllib.request.Request("http://%s/latest/meta-data/" % IP)  # root listing, not creds
        with urllib.request.urlopen(req, timeout=2) as r:
            v1_open = (r.status == 200)
    except Exception:
        v1_open = False
    if v1_open:
        return make_result("HS-07", "FAIL",
                           "IMDSv1 exposed: metadata root readable with no token (the SSRF-open case; "
                           "Capital One class). Credential path deliberately NOT probed.", imds="v1", **cite("HS-07"))
    return make_result("HS-07", "BLOCKED",
                       "metadata endpoint reachable but the no-token read was refused -- consistent with "
                       "IMDSv2-only (token required). Lower risk than v1.", imds="v2-or-blocked", **cite("HS-07"))


# ---- HS-08 provider agent reachable -----------------------------------------
def hs08_provider_agent():
    hits = []
    for sock in ("/var/run/vast.sock", "/run/vast.sock", "/var/run/runpod.sock",
                 "/var/run/provider.sock", "/tmp/agent.sock"):
        if os.path.exists(sock):
            hits.append("agent socket: %s" % sock)
    # common host-agent management ports on the gateway/host
    rc, route, _ = sh(["sh", "-c", "ip route | awk '/default/{print $3; exit}'"])
    gw = route.strip()
    for port in (8000, 8080, 5000, 6443, 2375, 2376):
        for host in filter(None, ("127.0.0.1", gw)):
            try:
                s = socket.socket(); s.settimeout(0.6)
                if s.connect_ex((host, port)) == 0:
                    hits.append("open management port %s:%d" % (host, port))
                s.close()
            except Exception:
                pass
    if not hits:
        return make_result("HS-08", "PASS", "no provider-agent socket or management port reachable from the container")
    return make_result("HS-08", "FAIL", "host-management surface reachable from inside the tenant: " + "; ".join(hits[:8]))


# ---- HS-09 VBIOS / firmware integrity ---------------------------------------
def hs09_vbios(expected):
    rc, out, _ = sh(["nvidia-smi", "--query-gpu=vbios_version", "--format=csv,noheader"])
    if rc != 0:
        return make_result("HS-09", "ERROR", "nvidia-smi query failed", **cite("HS-09"))
    vbios = [l.strip() for l in out.splitlines() if l.strip()]
    if not expected:
        return make_result("HS-09", "BLOCKED",
                           "VBIOS present: %s. Provide --expect-vbios to check against a known-good value; "
                           "build a per-GPU-model expected table over time." % vbios, vbios=vbios, **cite("HS-09"))
    ok = all(v == expected for v in vbios)
    if ok:
        return make_result("HS-09", "PASS", "VBIOS %s matches expected" % vbios, vbios=vbios, **cite("HS-09"))
    return make_result("HS-09", "FAIL", "VBIOS %s does not match expected %s" % (vbios, expected),
                       vbios=vbios, **cite("HS-09"))


# ---- HS-10 network egress openness ------------------------------------------
def hs10_egress():
    # Can the container open arbitrary outbound connections? Wide-open egress is
    # an exfiltration path. Test a few well-known hosts/ports; report what's open.
    targets = [("1.1.1.1", 53, "DNS"), ("1.1.1.1", 443, "HTTPS"),
               ("8.8.8.8", 443, "HTTPS-alt"), ("github.com", 22, "SSH"),
               ("1.1.1.1", 25, "SMTP")]
    open_ports = []
    for host, port, label in targets:
        try:
            s = socket.socket(); s.settimeout(1.5)
            if s.connect_ex((host, port)) == 0:
                open_ports.append("%s (%s:%d)" % (label, host, port))
            s.close()
        except Exception:
            pass
    # SMTP open outbound is a classic exfil/abuse signal
    risky = any("SMTP" in o for o in open_ports)
    if not open_ports:
        return make_result("HS-10", "PASS", "no outbound test ports reachable (egress appears restricted)")
    verdict = "FAIL" if risky else "BLOCKED"
    return make_result("HS-10", verdict,
                       "outbound reachable: %s%s" % (", ".join(open_ports),
                       " -- includes SMTP (exfil/abuse path)" if risky else " (open egress; note for the report)"),
                       open=open_ports)


# ---- SC-01 side-channel exposure (config only) ------------------------------
def sc01_sidechannel_config():
    # CONFIG ONLY. We read how THIS machine is arranged; we never observe a neighbour.
    rc, out, _ = sh(["nvidia-smi", "--query-gpu=mig.mode.current,compute_mode", "--format=csv,noheader"])
    factors = []
    for line in out.splitlines() if rc == 0 else []:
        v = [x.strip() for x in line.split(",")]
        try:
            mig, cmode = v
            if not mig.lower().startswith("enabled"):
                factors.append("no MIG isolation")
            if "default" in cmode.lower():
                factors.append("compute mode 'Default' (multiple processes can share the GPU)")
        except ValueError:
            pass
    # MPS daemon present = explicit sharing
    rc2, ps, _ = sh(["sh", "-c", "ps -e 2>/dev/null | grep -c '[n]vidia-cuda-mps'"])
    if rc2 == 0 and ps.strip().isdigit() and int(ps.strip()) > 0:
        factors.append("CUDA MPS daemon running (explicit multi-tenant GPU sharing)")
    factors = sorted(set(factors))
    if not factors:
        return make_result("SC-01", "PASS", "GPU arranged for isolation (MIG on / exclusive) -- co-tenant "
                           "observation surface minimal", **cite("SC-01"))
    return make_result("SC-01", "BLOCKED",
                       "machine is arranged so a co-tenant COULD in principle be observed via shared-GPU "
                       "side channels: %s. This is a configuration finding only; Watchdog does not observe "
                       "other tenants." % "; ".join(factors), factors=factors, **cite("SC-01"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True)
    ap.add_argument("--expect-vbios", default="")
    ap.add_argument("--out")
    a = ap.parse_args()
    probes = [hh06_host_ram, hh07_ipc, hh08_gpu_state, hh09_disk_logs, hh10_net_trace, hh11_leftoverlocals,
              hs06_toolkit, hs07_imds, hs08_provider_agent, lambda: hs09_vbios(a.expect_vbios),
              hs10_egress, sc01_sidechannel_config]
    results = [p() for p in probes]
    rc, host, _ = sh(["hostname"])
    doc = {"provider": a.provider, "host": host, "captured_utc": datetime.now(timezone.utc).isoformat(),
           "round": 2,
           "boundary": "own-instance only; HS-07 never reads credentials; SC-01 is config-only, never observes a neighbour",
           "results": results}
    name = a.out or "benchmark2_%s_%s.json" % (a.provider, datetime.now().strftime("%Y%m%d_%H%M%S"))
    with open(name, "w") as fh:
        json.dump(doc, fh, indent=2)
    print("WATCHDOG PROVIDER BENCHMARK round 2 -- %s  (own-instance only, cited)" % a.provider)
    for r in results:
        print("  %-6s %-40s %-8s %s" % (r["test_id"], r["title"][:40], r["verdict"], r["detail"][:80]))
        for lbl, url in r.get("evidence", {}).get("citations", []):
            print("           cite: %s" % lbl)
    tally = {}
    for r in results:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    print("\nTally: " + ", ".join("%s %d" % (k, tally[k]) for k in sorted(tally)))
    print("written: %s   (copy off the pod before releasing it)" % name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
