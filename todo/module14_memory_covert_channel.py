#!/usr/bin/env python3
"""
Watchdog — Module 14: CPU/GPU Memory Covert Channel
Detects suspicious memory usage patterns that may indicate cache-timing or DMA-driven exfil.
"""
import subprocess, time, datetime, json

DURATION_S = 120  # was fixed 300 iterations (~300s); standardized


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_gpu_memory_usage():
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.used,utilization.memory", "--format=csv,noheader,nounits"],
            text=True, timeout=3, stderr=subprocess.DEVNULL
        )
        parts = out.strip().split(",")
        if len(parts) >= 2:
            return float(parts[0]), float(parts[1])
        return 0.0, 0.0
    except Exception:
        return 0.0, 0.0


def get_cpu_memory_usage():
    try:
        out = subprocess.check_output(["free", "-m"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for l in out.splitlines():
            if "Mem:" in l:
                parts = l.split()
                if len(parts) >= 3:
                    return float(parts[1]), float(parts[2])
        return 0.0, 0.0
    except Exception:
        return 0.0, 0.0


def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module14_memory_covert_channel_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event": "RUN_START", "module": "14_memory_covert", "ts": now_iso()}) + "\n")

    alerts = 0
    prev_gpu_used, _ = get_gpu_memory_usage()
    _, prev_cpu_used = get_cpu_memory_usage()

    start = time.time()
    while time.time() < start + DURATION_S:
        gpu_used, _ = get_gpu_memory_usage()
        _, cpu_used = get_cpu_memory_usage()

        if prev_gpu_used > 0 and prev_cpu_used > 0:
            gpu_delta = abs(gpu_used - prev_gpu_used) / prev_gpu_used
            cpu_delta = abs(cpu_used - prev_cpu_used) / prev_cpu_used
            if gpu_delta > 0.5 and cpu_delta > 0.5:
                alerts += 1
                log.write(json.dumps({
                    "detector": "D89_MEMORY_COVERT_CHANNEL",
                    "severity": "WARN",
                    "gpu_delta_pct": round(gpu_delta * 100, 1),
                    "cpu_delta_pct": round(cpu_delta * 100, 1),
                    "confidence": 0.3,
                    "note": "Synchronized CPU/GPU memory changes — possible covert channel"
                }) + "\n")

        prev_gpu_used = gpu_used
        prev_cpu_used = cpu_used
        time.sleep(1.0)

    log.write(json.dumps({"event": "RUN_END", "alerts": alerts, "ts": now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 14: alerts={alerts}\nLog: {out}")


if __name__ == "__main__":
    main()
