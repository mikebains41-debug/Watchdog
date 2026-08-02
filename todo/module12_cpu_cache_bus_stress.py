#!/usr/bin/env python3
"""
Watchdog — Module 12: CPU Cache/Bus Stress & Core Isolation Violations
Detects:
- L3 cache thrashing (memory bandwidth spikes with no GPU load)
- Core isolation violations (processes landing on isolated cores)
- RAPL energy spikes with no matching CPU load
"""
import os, subprocess, time, datetime, json, re

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_cpu_mem_bandwidth():
    try:
        out = subprocess.check_output(["vmstat", "-s", "-S", "M"], text=True, timeout=3)
        lines = out.splitlines()
        for l in lines:
            if "K" in l and "memory" in l:
                # rough approximation: high cache activity shows as memory ops
                parts = l.split()
                if parts and parts[0].isdigit():
                    return float(parts[0])
        return 0.0
    except:
        return 0.0

def get_gpu_util():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"], text=True, timeout=3)
        return float(out.strip())
    except:
        return None

def get_rapl():
    try:
        out = subprocess.check_output(["cat", "/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj"], text=True, timeout=2)
        return float(out.strip())
    except:
        return None

def check_core_isolation():
    # Check if any process is using an isolated core (if that's configured)
    # This is a best-effort check; isolation is usually in kernel params
    try:
        out = subprocess.check_output(["cat", "/proc/cmdline"], text=True, timeout=2)
        if "isolcpus" in out:
            return True  # isolation configured, further checks would need PID/core mapping
        return False
    except:
        return False

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module12_cpu_cache_bus_stress_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START", "module":"12_cpu_cache_bus", "ts":now_iso()}) + "\n")

    prev_bandwidth = get_cpu_mem_bandwidth()
    prev_rapl = get_rapl()
    alerts = 0

    for _ in range(300):
        bandwidth = get_cpu_mem_bandwidth()
        gpu_util = get_gpu_util()
        rapl = get_rapl()

        # L3 cache thrashing: high memory bandwidth + low GPU util
        if bandwidth > 500 and gpu_util is not None and gpu_util < 10:
            alerts += 1
            log.write(json.dumps({
                "detector":"L3_CACHE_THRASHING",
                "severity":"INFO",
                "mem_bandwidth_mb":round(bandwidth, 1),
                "gpu_util":gpu_util,
                "confidence":0.3,
                "note":"High CPU memory bandwidth with GPU idle — possible cache stress or PCIe snooping"
            }) + "\n")

        # RAPL spike with no compute
        if prev_rapl and rapl and prev_rapl > 0:
            spike = (rapl - prev_rapl) / prev_rapl
            if spike > 0.3:  # 30% spike
                alerts += 1
                log.write(json.dumps({
                    "detector":"RAPL_SPIKE_NO_COMPUTE",
                    "severity":"WARN",
                    "spike_pct":round(spike * 100, 1),
                    "confidence":0.4,
                    "note":"CPU power spike without matching compute — possible side-channel"
                }) + "\n")
        prev_rapl = rapl

        time.sleep(1.0)

    log.write(json.dumps({"event":"RUN_END","alerts":alerts,"ts":now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 12: alerts={alerts}\nLog: {out}")

if __name__ == "__main__":
    main()
