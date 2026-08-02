#!/usr/bin/env python3
"""
Watchdog — Module 14: CPU/GPU Memory Covert Channel
Detects suspicious memory usage patterns that may indicate cache-timing or DMA-driven exfil.
"""
import subprocess, time, datetime, json

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_gpu_memory_usage():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=memory.used,utilization.memory", "--format=csv,noheader,nounits"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        parts = out.strip().split(",")
        if len(parts) >= 2:
            return float(parts[0]), float(parts[1])
        return 0.0, 0.0
    except:
        return 0.0, 0.0

def get_cpu_memory_usage():
    try:
        out = subprocess.check_output(["free", "-m"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        lines = out.splitlines()
        for l in lines:
            if "Mem:" in l:
                parts = l.split()
                if len(parts) >= 3:
                    return float(parts[1]), float(parts[2])
        return 0.0, 0.0
    except:
        return 0.0, 0.0

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module14_memory_covert_channel_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START", "module":"14_memory_covert", "ts":now_iso()}) + "\n")

    alerts = 0
    prev_gpu_used, prev_gpu_util = get_gpu_memory_usage()
    prev_cpu_total, prev_cpu_used = get_cpu_memory_usage()

    for _ in range(300):
        gpu_used, gpu_util = get_gpu_memory_usage()
        cpu_total, cpu_used = get_cpu_memory_usage()

        # Detect rapid memory syncs between CPU and GPU
        if prev_gpu_used > 0 and prev_cpu_used > 0:
            gpu_delta = abs(gpu_used - prev_gpu_used) / prev_gpu_used
            cpu_delta = abs(cpu_used - prev_cpu_used) / prev_cpu_used
            if gpu_delta > 0.5 and cpu_delta > 0.5:
                alerts += 1
                log.write(json.dumps({
                    "detector":"MEMORY_COVERT_CHANNEL",
                    "severity":"WARN",
                    "gpu_delta_pct":round(gpu_delta*100, 1),
                    "cpu_delta_pct":round(cpu_delta*100, 1),
                    "confidence":0.3,
                    "note":"Synchronized CPU/GPU memory changes — possible covert channel"
                }) + "\n")

        prev_gpu_used = gpu_used
        prev_cpu_used = cpu_used
        time.sleep(1.0)

    log.write(json.dumps({"event":"RUN_END","alerts":alerts,"ts":now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 14: alerts={alerts}\nLog: {out}")

if __name__ == "__main__":
    main()
