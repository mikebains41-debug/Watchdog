#!/usr/bin/env python3
"""
Watchdog — Module 1: NVML / nvidia-smi source
One pass over GPU telemetry. Detection-only (no pstate lock, no nvlink disable,
no context kill — those are roadmap/bare-metal). Safe on shared hardware: reads only.

Merged detections (all from nvidia-smi):
  D1 Ghost power/telemetry mismatch   D3 pstate transitions
  D4 Zero-syscall mine                D8 Thermal/power stress
  D71 Per-process GPU attribution
See DETECTOR_REGISTRY.md for the full, collision-free ID list.
"""
import argparse, json, subprocess, sys, time, datetime, shutil, os
from collections import defaultdict

POWER_HIGH_W = 600.0
UTIL_LOW_PCT = 20.0
D4_CONSEC = 10
GHOST_MARGIN_W = 40.0
PSTATE_JUMP = 2
TEMP_CEIL_C = 85.0
SAMPLE_HZ = 1.0
DURATION_S_DEFAULT = 120


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def have(c):
    return shutil.which(c) is not None


def num(v):
    try:
        return float(v)
    except Exception:
        return None


def q(fields):
    try:
        out = subprocess.check_output(
            ["nvidia-smi", f"--query-gpu={fields}", "--format=csv,noheader,nounits"],
            text=True, timeout=10, stderr=subprocess.DEVNULL,
        )
        return out.strip().splitlines()
    except Exception:
        return []


def sample_gpus():
    rows = []
    for line in q("index,pstate,utilization.gpu,power.draw,memory.used,memory.total,temperature.gpu"):
        p = [x.strip() for x in line.split(",")]
        if len(p) < 7:
            continue
        rows.append({
            "index": p[0], "pstate": p[1], "util": num(p[2]), "power": num(p[3]),
            "mem_used": num(p[4]), "mem_total": num(p[5]), "temp": num(p[6]),
        })
    return rows


def compute_apps():
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-compute-apps=gpu_uuid,pid,process_name,used_memory",
             "--format=csv,noheader,nounits"],
            text=True, timeout=10, stderr=subprocess.DEVNULL,
        )
        a = []
        for line in out.strip().splitlines():
            p = [x.strip() for x in line.split(",")]
            if len(p) >= 4:
                a.append({"uuid": p[0], "pid": p[1], "name": p[2], "mem_mib": p[3]})
        return a
    except Exception:
        return []


def topo():
    try:
        return subprocess.check_output(
            ["nvidia-smi", "topo", "-m"], text=True, timeout=10, stderr=subprocess.DEVNULL
        ).strip()[:1200]
    except Exception:
        return None


def nvlink_err():
    try:
        return subprocess.check_output(
            ["nvidia-smi", "nvlink", "-e"], text=True, timeout=10, stderr=subprocess.DEVNULL
        ).strip()[:800]
    except Exception:
        return None


class Log:
    def __init__(s, path):
        s.f = open(path, "a")
        s.path = path

    def emit(s, r):
        r["ts"] = now_iso()
        s.f.write(json.dumps(r) + "\n")
        s.f.flush()

    def close(s):
        s.f.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=DURATION_S_DEFAULT)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = a.out or f"module1_nvml_{stamp}.jsonl"
    log = Log(out)

    if not have("nvidia-smi"):
        log.emit({"event": "WARNING", "message": "nvidia-smi not found — module cannot run on this host"})
        log.emit({"event": "RUN_END", "samples": 0, "alerts": 0})
        log.close()
        print("nvidia-smi not found — run on the RunPod GPU pod.")
        sys.exit(1)

    prank = {f"P{i}": i for i in range(16)}
    prev = {}
    d4 = defaultdict(int)
    floor = {}
    samples = alerts = 0

    log.emit({"event": "RUN_START", "module": "1_nvml", "host": os.uname().nodename,
              "duration_s": a.duration, "note": "Detection-only. No remediation."})
    log.emit({"event": "TOPO", "topo": topo()})
    log.emit({"event": "NVLINK_ERR_BASELINE", "data": nvlink_err()})

    warm = []
    for _ in range(5):
        warm += [g["power"] for g in sample_gpus() if g["power"] is not None]
        time.sleep(0.5)
    base = (sum(warm) / len(warm)) if warm else 0.0

    t_end = time.time() + a.duration
    while time.time() < t_end:
        gpus = sample_gpus()
        apps = compute_apps()
        by = defaultdict(list)
        for ap_ in apps:
            by[ap_["uuid"]].append(ap_)

        for g in gpus:
            gi = g["index"]
            samples += 1
            floor.setdefault(gi, base)

            if g["power"] and g["util"] is not None:
                if g["power"] > floor[gi] + GHOST_MARGIN_W and g["util"] < UTIL_LOW_PCT:
                    alerts += 1
                    log.emit({"detector": "D1_GHOST_POWER", "severity": "WARN", "gpu": gi,
                               "power_w": g["power"], "util": g["util"],
                               "idle_floor_w": round(floor[gi], 1), "confidence": 0.7,
                               "note": "Power above idle floor while util low."})
                if g["power"] > POWER_HIGH_W and g["util"] < UTIL_LOW_PCT:
                    d4[gi] += 1
                    if d4[gi] == D4_CONSEC:
                        alerts += 1
                        log.emit({"detector": "D4_ZERO_SYSCALL_MINE", "severity": "CRITICAL",
                                   "gpu": gi, "power_w": g["power"], "util": g["util"],
                                   "consecutive": D4_CONSEC, "confidence": 0.85,
                                   "note": "High power + low util sustained — hidden kernel?"})
                else:
                    d4[gi] = 0

            ps = g["pstate"]
            if gi in prev and ps != prev[gi]:
                r0, r1 = prank.get(prev[gi]), prank.get(ps)
                jump = abs(r1 - r0) if (r0 is not None and r1 is not None) else None
                crit = jump is not None and jump > PSTATE_JUMP and (g["util"] or 0) < UTIL_LOW_PCT
                if crit:
                    alerts += 1
                log.emit({"detector": "D3_PSTATE", "severity": "CRITICAL" if crit else "INFO",
                           "gpu": gi, "from": prev[gi], "to": ps, "jump": jump, "util": g["util"],
                           "confidence": 0.75 if crit else 0.3,
                           "note": "Large pstate jump, no util rise." if crit else "pstate change."})
            prev[gi] = ps

            if g["temp"] and g["power"] and g["util"] is not None:
                if g["temp"] >= TEMP_CEIL_C and g["power"] > POWER_HIGH_W and g["util"] < UTIL_LOW_PCT:
                    alerts += 1
                    log.emit({"detector": "D8_THERMAL_STRESS", "severity": "CRITICAL", "gpu": gi,
                               "temp_c": g["temp"], "power_w": g["power"], "util": g["util"],
                               "confidence": 0.8, "note": "Heat+power at ceiling without matching compute."})

            owners = by.get(gi) or []
            if g["mem_used"] and g["mem_used"] > 1024 and not owners:
                log.emit({"detector": "D71_GPU_MEM_ATTRIBUTION", "severity": "WARN", "gpu": gi,
                           "mem_used_mib": g["mem_used"], "owners": 0, "confidence": 0.5,
                           "note": "GPU memory in use but no compute-app owner reported."})

        time.sleep(1.0 / SAMPLE_HZ)

    log.emit({"event": "NVLINK_ERR_FINAL", "data": nvlink_err()})
    log.emit({"event": "RUN_END", "samples": samples, "alerts": alerts})
    log.close()
    print(f"Done. samples={samples} alerts={alerts}\nLog: {out}")


if __name__ == "__main__":
    main()
