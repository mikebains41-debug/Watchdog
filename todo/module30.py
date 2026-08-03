#!/usr/bin/env python3
"""
Watchdog — Module 30: GPU Page Retirement Poisoning Prevention (B200/HBM3e)
Attack: Attacker toggles faulty HBM3e pages on/off, causing repeated
        retire/unretire cycles that stutter the memory controller and
        stall training jobs.
Prevention:
  - Monitors retired_pages.pending + retired_pages.total (correct field names)
  - >5 changes in 30s → nvidia-smi --gpu-reset
  - Also tracks double-bit (uncorrectable) ECC errors which accompany real attacks

Correction from original spec: '--query-gpu=retired_pages' is not a valid field.
Real fields: 'retired_pages.pending' and 'retired_pages.total'
"""
import subprocess, time, datetime, json
from collections import deque

CHANGE_THRESHOLD   = 5    # retirement count changes before action
CHANGE_WINDOW      = 30   # seconds
POLL_INTERVAL      = 2    # seconds
RESET_COOLDOWN     = 60   # seconds between GPU resets
MIN_RETIRE_DELTA   = 1    # minimum page count change to register as an event

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def get_retired_pages() -> dict:
    """
    Query retired page counts. Returns dict with pending/total/sbe/dbe counts.
    Uses correct nvidia-smi field names for B200 driver.
    """
    fields = ",".join([
        "retired_pages.pending",
        "retired_pages.total",
        "ecc.errors.uncorrected.volatile.total",   # double-bit errors
        "ecc.errors.corrected.volatile.total",
    ])
    try:
        out = subprocess.check_output(
            ["nvidia-smi", f"--query-gpu={fields}",
             "--format=csv,noheader,nounits"],
            text=True, timeout=3)
        parts = [p.strip() for p in out.strip().split(",")]
        if len(parts) >= 4:
            return {
                "pending": int(parts[0]) if parts[0].isdigit() else 0,
                "total":   int(parts[1]) if parts[1].isdigit() else 0,
                "dbe":     int(parts[2]) if parts[2].isdigit() else 0,
                "sbe":     int(parts[3]) if parts[3].isdigit() else 0,
            }
    except:
        pass

    # Driver version fallback — try individual fields
    result = {"pending": 0, "total": 0, "dbe": 0, "sbe": 0}
    for key, field in [
        ("pending", "retired_pages.pending"),
        ("total",   "retired_pages.total"),
        ("dbe",     "ecc.errors.uncorrected.volatile.total"),
    ]:
        try:
            out = subprocess.check_output(
                ["nvidia-smi", f"--query-gpu={field}",
                 "--format=csv,noheader,nounits"],
                text=True, timeout=2)
            val = out.strip()
            result[key] = int(val) if val.isdigit() else 0
        except:
            pass
    return result

def reset_gpu() -> bool:
    try:
        subprocess.check_output(
            ["nvidia-smi", "--gpu-reset", "-i", "0"],
            text=True, timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    log = open(f"module30_vram_retirement_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "30_vram_retirement", "gpu": "B200",
          "memory": "HBM3e", "change_threshold": CHANGE_THRESHOLD,
          "window_s": CHANGE_WINDOW,
          "fields": ["retired_pages.pending", "retired_pages.total"]})

    prev        = get_retired_pages()
    change_times = deque()    # timestamps of retirement changes
    last_reset  = 0.0

    emit({"event": "BASELINE", "retired": prev})

    while True:
        time.sleep(POLL_INTERVAL)
        now     = time.time()
        current = get_retired_pages()

        # Detect any change in retirement counts
        pending_delta = abs(current["pending"] - prev["pending"])
        total_delta   = abs(current["total"]   - prev["total"])

        if pending_delta >= MIN_RETIRE_DELTA or total_delta >= MIN_RETIRE_DELTA:
            change_times.append(now)
            emit({"event": "PAGE_RETIREMENT_CHANGE",
                  "prev_pending":    prev["pending"],
                  "curr_pending":    current["pending"],
                  "prev_total":      prev["total"],
                  "curr_total":      current["total"],
                  "dbe":             current["dbe"],
                  "delta_pending":   pending_delta,
                  "delta_total":     total_delta})

        # Purge outside window
        while change_times and (now - change_times[0]) > CHANGE_WINDOW:
            change_times.popleft()

        # Double-bit errors alone are critical — immediate reset
        if current["dbe"] > prev["dbe"] + 5:
            emit({"event": "UNCORRECTABLE_ECC_SPIKE",
                  "prev_dbe": prev["dbe"], "curr_dbe": current["dbe"],
                  "severity": "CRITICAL"})
            if now - last_reset > RESET_COOLDOWN:
                if reset_gpu():
                    emit({"event": "GPU_RESET_DBE",
                          "action": "nvidia-smi --gpu-reset"})
                    last_reset = now

        # Rapid retirement cycling = poisoning attack
        elif len(change_times) >= CHANGE_THRESHOLD and \
             now - last_reset > RESET_COOLDOWN:
            emit({"event": "PAGE_RETIREMENT_POISONING_DETECTED",
                  "changes_in_window": len(change_times),
                  "window_s": CHANGE_WINDOW,
                  "current": current})
            if reset_gpu():
                emit({"event": "GPU_RESET_RETIREMENT",
                      "action": "nvidia-smi --gpu-reset"})
                last_reset = now
                change_times.clear()

        prev = current

if __name__ == "__main__":
    main()
