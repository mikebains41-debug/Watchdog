#!/usr/bin/env python3
"""
Watchdog — Cache Noise Injector (B200 host)
Attack: Prime+Probe L3 cache covert channel.
        Attacker times memory accesses to derive neighbor tenant's model architecture.
        Signature: LLC miss rate shows RHYTHMIC PULSE (regular periodic spikes)
        rather than random noise — indicates timed cache-probing.

Prevention:
  - Samples LLC miss rate every 500ms over a rolling window
  - Detects periodicity using coefficient of variation + autocorrelation
  - On detection: thrashes L3 with stress-ng (correct) or large random-access
    Python buffer (fallback) — NOT dd if=/dev/zero which stays in L1/L2
"""
import subprocess, time, datetime, json, os, math, threading
from collections import deque

SAMPLE_INTERVAL  = 0.5    # seconds between LLC miss samples
WINDOW_SIZE      = 20     # samples in analysis window (~10s)
# A rhythmic probe has LOW variance relative to mean — regular pattern
# CV (std/mean) < threshold indicates suspiciously regular miss rate
CV_THRESHOLD     = 0.15   # coefficient of variation below this = periodic
MIN_MISS_RATE    = 1000   # ignore windows where misses are too low (idle)
THRASH_DURATION  = 5      # seconds of cache thrashing
THRASH_COOLDOWN  = 30     # seconds before re-thrashing
CACHE_SIZE_MB    = 128    # bytes to access for thrashing (> L3 size to evict)

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def get_llc_misses() -> float:
    """Sample LLC-load-misses over 500ms via perf."""
    try:
        out = subprocess.check_output(
            ["perf", "stat", "-e", "LLC-load-misses",
             "-x", ",", "sleep", "0.5"],
            text=True, timeout=3, stderr=subprocess.STDOUT)
        for line in out.strip().splitlines():
            parts = line.split(",")
            try:
                return float(parts[0].replace(",", "").strip())
            except:
                continue
        return 0.0
    except:
        return 0.0

def is_periodic(samples: list) -> tuple[bool, dict]:
    """
    Detect rhythmic/periodic pattern in miss rate samples.
    Prime+Probe attacks produce regular periodic spikes unlike random noise.
    Uses Coefficient of Variation: low CV = suspiciously regular.
    """
    if len(samples) < WINDOW_SIZE:
        return False, {}

    mean = sum(samples) / len(samples)
    if mean < MIN_MISS_RATE:
        return False, {}

    variance = sum((x - mean) ** 2 for x in samples) / len(samples)
    std      = math.sqrt(variance)
    cv       = std / mean if mean > 0 else 1.0

    # Also check for autocorrelation at lag 1 (periodic signal has high lag-1 AC)
    lag1_ac = 0.0
    if std > 0:
        pairs = [(samples[i] - mean) * (samples[i+1] - mean)
                 for i in range(len(samples)-1)]
        lag1_ac = (sum(pairs) / (len(pairs) * variance)) if variance > 0 else 0

    suspicious = cv < CV_THRESHOLD and lag1_ac > 0.5

    return suspicious, {
        "mean": round(mean, 1),
        "cv": round(cv, 4),
        "lag1_autocorr": round(lag1_ac, 4)
    }

def thrash_cache_stressng(duration: int) -> bool:
    """Use stress-ng to thrash L3 cache — correct method."""
    try:
        subprocess.check_output(
            ["stress-ng", "--cache", "1",
             f"--timeout", f"{duration}s", "--quiet"],
            timeout=duration + 5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def thrash_cache_python(duration: int):
    """
    Fallback: allocate and randomly access a buffer larger than L3.
    This forces cache eviction across all sets, breaking attacker's timing.
    """
    import random
    size  = CACHE_SIZE_MB * 1024 * 1024 // 8   # as 64-bit ints
    buf   = bytearray(size)
    end   = time.time() + duration
    step  = max(1, size // 100000)
    while time.time() < end:
        # Random strided access to evict cache lines across all sets
        idx = random.randrange(0, len(buf) - 64, 64)
        buf[idx] ^= 0xFF

def thrash_cache(duration: int) -> str:
    """Try stress-ng first, fall back to Python buffer thrash."""
    if thrash_cache_stressng(duration):
        return "stress-ng"
    else:
        t = threading.Thread(target=thrash_cache_python, args=(duration,), daemon=True)
        t.start()
        return "python_buffer"

def main():
    log = open(f"watchdog_cache_noise_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "cache_noise_injector", "gpu": "B200",
          "cv_threshold": CV_THRESHOLD, "window_size": WINDOW_SIZE,
          "thrash_method": "stress-ng (python buffer fallback)"})

    samples       = deque(maxlen=WINDOW_SIZE)
    last_thrash   = 0.0

    while True:
        misses = get_llc_misses()
        samples.append(misses)

        if len(samples) == WINDOW_SIZE:
            periodic, stats = is_periodic(list(samples))

            if periodic and time.time() - last_thrash > THRASH_COOLDOWN:
                emit({"event": "PRIME_PROBE_DETECTED",
                      "stats": stats,
                      "action": f"thrash_l3_{THRASH_DURATION}s"})

                method = thrash_cache(THRASH_DURATION)
                emit({"event": "CACHE_THRASH_COMPLETE",
                      "duration_s": THRASH_DURATION,
                      "method": method})

                last_thrash = time.time()
                samples.clear()   # Reset window after intervention

        # Don't sleep — get_llc_misses() already takes 500ms

if __name__ == "__main__":
    main()
