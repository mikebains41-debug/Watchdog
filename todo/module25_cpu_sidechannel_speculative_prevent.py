#!/usr/bin/env python3
"""
Watchdog — Module 25: CPU Side-Channel & Speculative Prevention
Combines:
- cpu_smt_sidechannel_prevent.py (SMT / Hyperthreading covert channels)
- cpu_spectre_meltdown_prevent.py (Spectre/Meltdown speculative execution)
- cpu_cache_timing_mitigator.py (L1/L2 cache timing side-channels)
"""
import subprocess, time, datetime, json, os

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def check_dmesg_for_spectre():
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "spectre" in line.lower() or "meltdown" in line.lower():
                if "vulnerable" in line.lower():
                    return line.strip()
        return None
    except:
        return None

def disable_smt():
    try:
        subprocess.check_output(["echo", "off", ">", "/sys/devices/system/cpu/smt/control"], shell=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def flush_cache():
    try:
        subprocess.check_output(["echo", "1", ">", "/proc/sys/vm/drop_caches"], shell=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def get_llc_misses():
    try:
        out = subprocess.check_output(["perf", "stat", "-e", "LLC-load-misses", "-x", ",", "sleep", "1"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        first = out.strip().splitlines()[0]
        return float(first.split(",")[0])
    except:
        return 0

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module25_cpu_sidechannel_speculative_prevent_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"25_cpu_sidechannel_speculative","ts":now_iso()}) + "\n")

    baseline = get_llc_misses()
    while True:
        line = check_dmesg_for_spectre()
        if line:
            if flush_cache():
                log.write(json.dumps({
                    "event":"SPECTRE_CACHE_FLUSH",
                    "log":line,
                    "action":"cache_flush"
                }) + "\n")

        misses = get_llc_misses()
        if baseline > 0 and misses > baseline * 5:
            if disable_smt():
                log.write(json.dumps({
                    "event":"SMT_DISABLED",
                    "baseline":baseline,
                    "current":misses,
                    "action":"smt_off"
                }) + "\n")
        time.sleep(2)

if __name__ == "__main__":
    main()
