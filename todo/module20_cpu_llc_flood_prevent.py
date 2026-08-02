#!/usr/bin/env python3
"""
Watchdog — Module 20: CPU LLC Flood Prevention
"""
import subprocess, time, datetime, json

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

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

def lock_cpu_low():
    try:
        # -f takes Hz
        subprocess.check_output(["cpupower", "frequency-set", "-f", "800000"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def unlock_cpu():
    try:
        # -g takes governor name
        subprocess.check_output(["cpupower", "frequency-set", "-g", "performance"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module20_cpu_llc_flood_prevent_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"20_cpu_llc_flood","ts":now_iso()}) + "\n")

    baseline = get_llc_misses()
    while True:
        misses = get_llc_misses()
        if baseline > 0 and misses > baseline * 5:
            if lock_cpu_low():
                log.write(json.dumps({
                    "event":"LLC_FLOOD_LOCK",
                    "baseline":baseline,
                    "current":misses,
                    "action":"800MHz"
                }) + "\n")
                time.sleep(5)
                if unlock_cpu():
                    log.write(json.dumps({"event":"LLC_UNLOCK"}) + "\n")  # fixed: was missing \n
        time.sleep(2)

if __name__ == "__main__":
    main()
