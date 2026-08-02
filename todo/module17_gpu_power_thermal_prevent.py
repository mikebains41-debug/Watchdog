#!/usr/bin/env python3
"""
Watchdog — Module 17: GPU Power & Thermal Prevention
Combines:
- gpu_thermal_attack_prevent.py (fan 100% + power limit 50W on thermal stress)
- gpu_pstate_lock.py (force P-state lock on P-state hijack)
"""
import subprocess, time, datetime, json

TEMP_THRESHOLD = 85
PSTATE_JUMP_LIMIT = 2
UTIL_LOW = 20

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_gpu_util():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"], text=True, timeout=2)
        return float(out.strip())
    except:
        return None

def get_temp():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"], text=True, timeout=2)
        return float(out.strip())
    except:
        return None

def get_pstate():
    try:
        out = subprocess.check_output(["nvidia-smi", "-q", "-d", "CLOCK"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "Performance State" in line:
                return line.split(":")[-1].strip()
        return None
    except:
        return None

def set_fan_speed(pct):
    try:
        subprocess.check_output(["nvidia-smi", "--fan-speed", f"{pct}"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def set_power_limit(w):
    try:
        subprocess.check_output(["nvidia-smi", "-pl", str(w)], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def lock_pstate():
    try:
        subprocess.check_output(["nvidia-smi", "-ac", "0,1"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module17_gpu_power_thermal_prevent_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"17_gpu_power_thermal","ts":now_iso()}) + "\n")

    prev_pstate = get_pstate()
    while True:
        util = get_gpu_util()
        temp = get_temp()
        pstate = get_pstate()

        if util is not None and temp is not None:
            if temp > TEMP_THRESHOLD and util < UTIL_LOW:
                if set_fan_speed(100) or set_power_limit(50):
                    log.write(json.dumps({
                        "event":"GPU_THERMAL_PREVENT",
                        "temp_c":temp,
                        "action":"fan100 + power50W"
                    }) + "\n")

        if prev_pstate and pstate and util is not None:
            try:
                jump = abs(int(pstate) - int(prev_pstate))
                if jump > PSTATE_JUMP_LIMIT and util < UTIL_LOW:
                    if lock_pstate():
                        log.write(json.dumps({
                            "event":"GPU_PSTATE_LOCK",
                            "from":prev_pstate,
                            "to":pstate,
                            "action":"pstate_locked"
                        }) + "\n")
            except:
                pass
        prev_pstate = pstate
        time.sleep(2)

if __name__ == "__main__":
    main()
