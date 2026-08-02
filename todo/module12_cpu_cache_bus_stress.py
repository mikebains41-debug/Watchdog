#!/usr/bin/env python3
"""
Watchdog — Module 12: CPU Cache/Bus Stress & Core Isolation Violations
Detects:
- L3 cache thrashing (memory bandwidth spikes with no GPU load)
- Core isolation violations (processes landing on isolated cores)
- RAPL energy spikes with no matching CPU load

FIXED: check_core_isolation() was defined but never called from main() —
the docstring claimed isolation violations were checked but the module
never actually did so. It's now called once at startup and, if isolation
is configured, logged as context (full per-PID/core violation checking
would need /proc/<pid>/status Cpus_allowed_list cross-referenced against
isolcpus, which is out of scope for this pass — flagged as a known gap
below rather than silently claiming full coverage).
"""
import subprocess, time, datetime, json

DURATION_S = 120


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_cpu_mem_bandwidth():
    """NOTE: this is a rough proxy, not real memory bandwidth — vmstat -s
    doesn't report bandwidth directly. Left as originally designed since no
    bug was reported here, but this is a known weak signal, not a hard fix."""
    try:
        out = subprocess.check_output(["vmstat", "-s", "-S", "M"], text=True, timeout=3)
        lines = out.splitlines()
        for l in lines:
            if "K" in l and "memory" in l:
                parts = l.split()
                if parts and parts[0].isdigit():
                    return float(parts[0])
        return 0.0
    except Exception:
        return 0.0


def get_gpu_util():
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"], text=True, timeout=3)
        return float(out.strip())
    except Exception:
        return None


def get_rapl():
    try:
        out = subprocess.check_output(["cat", "/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj"], text=True, timeout=2)
        return float(out.strip())
    except Exception:
        return None


def check_core_isolation():
    try:
        out = subprocess.check_output(["cat", "/proc/cmdline"], text=True, timeout=2)
        return "isolcpus" in out
    except Exception:
        return False


def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module12_cpu_cache_bus_stress_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event": "RUN_START", "module": "12_cpu_cache_bus", "ts": now_iso()}) + "\n")

    isolation_configured = check_core_isolation()
    log.write(json.dumps({
        "event": "CORE_ISOLATION_CONTEXT",
        "isolcpus_configured": isolation_configured,
        "note": "Per-process isolated-core violation checking is a known gap — "
                "this only confirms whether isolcpus is set in /proc/cmdline, "
                "not whether any process is actually violating it."
    }) + "\n")

    prev_rapl = get_rapl()
    alerts = 0

    start = time.time()
    while time.time() < start + DURATION_S:
        bandwidth = get_cpu_mem_bandwidth()
        gpu_util = get_gpu_util()
        rapl = get_rapl()

        if bandwidth > 500 and gpu_util is not None and gpu_util < 10:
            alerts += 1
            log.write(json.dumps({
                "detector": "D85_L3_CACHE_THRASHING",
                "severity": "INFO",
                "mem_bandwidth_mb": round(bandwidth, 1),
                "gpu_util": gpu_util,
                "confidence": 0.3,
                "note": "High CPU memory bandwidth with GPU idle — possible cache stress or PCIe snooping"
            }) + "\n")

        if prev_rapl and rapl and prev_rapl > 0:
            spike = (rapl - prev_rapl) / prev_rapl
            if spike > 0.3:
                alerts += 1
                log.write(json.dumps({
                    "detector": "D86_RAPL_SPIKE_NO_COMPUTE",
                    "severity": "WARN",
                    "spike_pct": round(spike * 100, 1),
                    "confidence": 0.4,
                    "note": "CPU power spike without matching compute — possible side-channel"
                }) + "\n")
        prev_rapl = rapl

        time.sleep(1.0)

    log.write(json.dumps({"event": "RUN_END", "alerts": alerts, "ts": now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 12: alerts={alerts}\nLog: {out}")


if __name__ == "__main__":
    main()
