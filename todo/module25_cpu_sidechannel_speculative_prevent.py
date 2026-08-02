#!/usr/bin/env python3
"""
Watchdog — Module 25: CPU Side-Channel & Speculative Prevention
"""
import subprocess, time, datetime, json

SPECTRE_COOLDOWN = 1800  # 30 min — dmesg lines are static after boot, avoid infinite loop

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
        with open("/sys/devices/system/cpu/smt/control", "w") as f:
            f.write("off")
        return True
    except:
        return False

def flush_cache():
    try:
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3")
        return True
    except:
        return False

def get_llc_misses():
    try:
        out = subprocess.check_output(
            ["perf", "stat", "-e", "LLC-load-misses", "-x", ",", "sleep", "1"],
            text=True, timeout=4, stderr=subprocess.STDOUT
        )
        for line in out.strip().splitlines():
            parts = line.split(",")
            try:
                return float(parts[0].replace(",", "").strip())
            except:
                continue
        return 0
    except:
        return 0

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module25_cpu_sidechannel_speculative_prevent_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"25_cpu_sidechannel_speculative","ts":now_iso()}) + "\n")

    baseline = get_llc_misses()
    last_spectre_trigger = 0

    while True:
        now = time.time()
        if now - last_spectre_trigger > SPECTRE_COOLDOWN:
            line = check_dmesg_for_spectre()
            if line:
                if flush_cache():
                    log.write(json.dumps({
                        "event":"SPECTRE_CACHE_FLUSH",
                        "log":line,
                        "action":"cache_flush"
                    }) + "\n")
                    last_spectre_trigger = now

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
