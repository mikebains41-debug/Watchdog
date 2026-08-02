#!/usr/bin/env python3
"""
Watchdog — Module 26: GPU Clock Glitch Prevention
"""
import subprocess, time, datetime, json

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_clocks():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=clocks.sm", "--format=csv,noheader,nounits"], text=True, timeout=2)
        return float(out.strip())
    except:
        return None

def lock_clock():
    try:
        subprocess.check_output(["nvidia-smi", "-ac", "0,1"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module26_gpu_clock_glitch_prevent_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"26_gpu_clock_glitch","ts":now_iso()}) + "\n")

    prev_clock = get_clocks()
    prev_time = time.time()

    while True:
        clock = get_clocks()
        now = time.time()
        if prev_clock and clock:
            if clock < prev_clock * 0.5:
                delta = (now - prev_time) * 1000
                if delta < 100:
                    if lock_clock():
                        log.write(json.dumps({
                            "event":"GPU_CLOCK_GLITCH_BLOCKED",
                            "old_mhz":prev_clock,
                            "new_mhz":clock,
                            "delta_ms":round(delta, 1),
                            "action":"clock_locked"
                        }) + "\n")
        prev_clock = clock
        prev_time = now
        time.sleep(0.5)

if __name__ == "__main__":
    main()
