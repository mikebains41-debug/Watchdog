#!/usr/bin/env python3
"""
Watchdog — Module 21: VRAM Rowhammer Prevention
"""
import subprocess, time, datetime, json
from collections import deque

ECC_WINDOW = 10
SPIKE_THRESHOLD = 10

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_ecc():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=ecc.errors.corrected.volatile.total", "--format=csv,noheader,nounits"], text=True, timeout=2)
        return float(out.strip())
    except:
        return None

def reset_gpu():
    try:
        subprocess.check_output(["nvidia-smi", "--gpu-reset", "-i", "0"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module21_vram_rowhammer_prevent_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"21_vram_rowhammer","ts":now_iso()}) + "\n")

    history = deque(maxlen=ECC_WINDOW)
    while True:
        ecc = get_ecc()
        if ecc is not None:
            history.append(ecc)
            if len(history) == ECC_WINDOW:
                baseline = sum(list(history)[:-1]) / (ECC_WINDOW - 1)
                if baseline > 0 and ecc > baseline * SPIKE_THRESHOLD:
                    if reset_gpu():
                        log.write(json.dumps({
                            "event":"VRAM_ROWHAMMER_PREVENT",
                            "ecc":ecc,
                            "baseline":round(baseline, 1),
                            "action":"gpu_reset"
                        }) + "\n")
        time.sleep(1)

if __name__ == "__main__":
    main()
