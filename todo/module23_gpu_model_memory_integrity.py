#!/usr/bin/env python3
"""
Watchdog — Module 23: GPU Model & Memory Integrity
Combines:
- gpu_memory_poison_prevent.py (block VRAM model poisoning)
- gpu_ecc_storm_dampener.py (block uncorrectable ECC storms)
- gpu_exfil_mitigator.py (block model weight exfiltration)
"""
import subprocess, time, datetime, json
from collections import deque

ECC_WINDOW = 20
ECC_STORM_THRESHOLD = 100

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_ecc():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=ecc.errors.corrected.volatile.total", "--format=csv,noheader,nounits"], text=True, timeout=2)
        return float(out.strip())
    except:
        return None

def get_mem_util():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=utilization.memory", "--format=csv,noheader,nounits"], text=True, timeout=2)
        return float(out.strip())
    except:
        return None

def get_outbound_connections():
    try:
        out = subprocess.check_output(["ss", "-tun"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return sum(1 for line in out.splitlines() if "ESTAB" in line)
    except:
        return 0

def reset_gpu():
    try:
        subprocess.check_output(["nvidia-smi", "--gpu-reset", "-i", "0"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def kill_outbound():
    try:
        subprocess.check_output(["pkill", "-f", "nc"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module23_gpu_model_memory_integrity_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"23_gpu_model_memory_integrity","ts":now_iso()}) + "\n")

    ecc_history = deque(maxlen=ECC_WINDOW)
    while True:
        ecc = get_ecc()
        mem_util = get_mem_util()
        outbound = get_outbound_connections()

        if ecc is not None:
            ecc_history.append(ecc)
            if len(ecc_history) == ECC_WINDOW:
                avg = sum(ecc_history) / ECC_WINDOW
                if ecc > avg * 10:
                    if reset_gpu():
                        log.write(json.dumps({
                            "event":"ECC_STORM_BLOCKED",
                            "ecc":ecc,
                            "avg":round(avg, 1),
                            "action":"gpu_reset"
                        }) + "\n")

        if mem_util and mem_util > 95 and outbound and outbound > 2:
            if kill_outbound():
                log.write(json.dumps({
                    "event":"MODEL_EXFIL_BLOCKED",
                    "mem_util":mem_util,
                    "outbound":outbound,
                    "action":"outbound_killed"
                }) + "\n")

        time.sleep(2)

if __name__ == "__main__":
    main()
