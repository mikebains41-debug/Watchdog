#!/usr/bin/env python3
"""
Watchdog — Module 28: NVLink IPG Timing Attack Prevention (B200)
Attack: Attacker measures inter-packet gaps on NVLink to deduce what data
        is being transferred (model weights vs prompts vs responses) without
        ever accessing the data directly.
Prevention:
  - Samples NVLink bandwidth every 500ms over 5s rolling window (10 samples)
  - Calculates jitter as standard deviation of bandwidth samples
  - If jitter > 3σ of baseline → inject noise via cupy GPU memcpy
  - Falls back to nvidia-smi triggered operation if cupy unavailable

Note: cudaMemcpy injection requires cupy (pip install cupy-cuda12x).
Fallback uses nvidia-smi to trigger a small GPU operation as noise.
"""
import subprocess, time, datetime, json, math, re
from collections import deque

try:
    import cupy as cp
    CUPY_AVAILABLE = True
except ImportError:
    CUPY_AVAILABLE = False

SAMPLE_INTERVAL  = 0.5    # seconds between NVLink samples
WINDOW_SIZE      = 10     # samples = 5s window
BASELINE_SAMPLES = 30     # samples to establish baseline
SIGMA_THRESHOLD  = 3.0    # standard deviations above baseline jitter
NOISE_DURATION   = 0.01   # seconds for cudaMemcpy noise injection (10ms)
NOISE_SIZE_MB    = 64     # MB to transfer for noise
COOLDOWN         = 10     # seconds between noise injections
NVLINK_LINKS     = 18     # B200 NV18

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def parse_nvlink_counters(raw: str) -> int:
    """Parse nvidia-smi nvlink -c output. Returns total KB/s across all links."""
    total = 0
    unit_mult = {"KB/s": 1, "MB/s": 1024, "GB/s": 1024 * 1024}
    for line in raw.splitlines():
        m = re.search(
            r'Link\s+\d+:.*?(\d+(?:\.\d+)?)\s+(KB/s|MB/s|GB/s)',
            line, re.IGNORECASE)
        if m:
            total += int(float(m.group(1)) * unit_mult.get(m.group(2), 1))
    return total

def get_nvlink_bw() -> int:
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "nvlink", "-c", "-i", "0"],
            text=True, timeout=5, stderr=subprocess.DEVNULL)
        return parse_nvlink_counters(out)
    except:
        return 0

def stddev(values: list) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(sum((x - mean) ** 2 for x in values) / len(values))

def inject_noise_cupy() -> bool:
    """Transfer random data GPU0→GPU1 to raise NVLink noise floor."""
    try:
        size = NOISE_SIZE_MB * 1024 * 1024 // 4   # float32 elements
        with cp.cuda.Device(0):
            src = cp.random.random(size, dtype=cp.float32)
        with cp.cuda.Device(1):
            dst = cp.empty(size, dtype=cp.float32)
        # P2P copy
        cp.cuda.runtime.memcpy(
            dst.data.ptr, src.data.ptr,
            size * 4, cp.cuda.runtime.memcpyDeviceToDevice)
        cp.cuda.stream.get_current_stream().synchronize()
        return True
    except:
        return False

def inject_noise_fallback() -> bool:
    """Fallback: trigger nvidia-smi query burst to create bus activity."""
    try:
        for _ in range(5):
            subprocess.check_output(
                ["nvidia-smi", "--query-gpu=memory.used,utilization.gpu",
                 "--format=csv,noheader,nounits"],
                text=True, timeout=2)
        return True
    except:
        return False

def inject_noise() -> tuple:
    if CUPY_AVAILABLE:
        ok = inject_noise_cupy()
        return ok, "cupy_p2p_memcpy"
    else:
        ok = inject_noise_fallback()
        return ok, "nvidia_smi_burst_fallback"

def main():
    log = open(f"module28_nvlink_ipg_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "28_nvlink_ipg", "gpu": "B200",
          "nvlink_links": NVLINK_LINKS, "cupy_available": CUPY_AVAILABLE,
          "sigma_threshold": SIGMA_THRESHOLD, "window_size": WINDOW_SIZE})

    # Establish baseline jitter
    baseline_samples = deque(maxlen=BASELINE_SAMPLES)
    emit({"event": "BASELINE_COLLECTION", "samples_needed": BASELINE_SAMPLES})

    for _ in range(BASELINE_SAMPLES):
        baseline_samples.append(get_nvlink_bw())
        time.sleep(SAMPLE_INTERVAL)

    baseline_jitter = stddev(list(baseline_samples))
    emit({"event": "BASELINE_ESTABLISHED",
          "baseline_jitter_kbs": round(baseline_jitter, 2),
          "mean_kbs": round(sum(baseline_samples)/len(baseline_samples), 2)})

    window     = deque(maxlen=WINDOW_SIZE)
    last_noise = 0.0

    while True:
        bw = get_nvlink_bw()
        window.append(bw)

        if len(window) == WINDOW_SIZE:
            current_jitter = stddev(list(window))
            threshold      = baseline_jitter * SIGMA_THRESHOLD \
                             if baseline_jitter > 0 else 1000

            if current_jitter > threshold and \
               time.time() - last_noise > COOLDOWN:
                emit({"event": "NVLINK_IPG_ATTACK_DETECTED",
                      "current_jitter_kbs": round(current_jitter, 2),
                      "baseline_jitter_kbs": round(baseline_jitter, 2),
                      "sigma": round(current_jitter / baseline_jitter, 2)
                             if baseline_jitter > 0 else 0})

                ok, method = inject_noise()
                if ok:
                    emit({"event": "NVLINK_NOISE_INJECTED",
                          "method": method,
                          "size_mb": NOISE_SIZE_MB})
                last_noise = time.time()

        time.sleep(SAMPLE_INTERVAL)

if __name__ == "__main__":
    main()
