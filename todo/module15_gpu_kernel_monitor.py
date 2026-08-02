#!/usr/bin/env python3
"""
Watchdog — Module 15: GPU Driver & Kernel Module Monitoring
Scans kernel modules and driver logs for unexpected additions to the GPU stack.
"""
import subprocess, datetime, json


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_loaded_modules():
    try:
        out = subprocess.check_output(["lsmod"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        lines = out.splitlines()
        modules = []
        for l in lines[1:]:
            parts = l.split()
            if len(parts) >= 3:
                modules.append(parts[0])
        return modules
    except Exception:
        return []


def get_kernel_logs():
    try:
        out = subprocess.check_output(["dmesg", "-T"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        alerts = []
        for l in out.splitlines():
            if "nvidia" in l.lower() or "cuda" in l.lower() or "gpu" in l.lower():
                alerts.append(l.strip())
        return alerts
    except Exception:
        return []


def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module15_gpu_kernel_monitor_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event": "RUN_START", "module": "15_gpu_kernel_monitor", "ts": now_iso()}) + "\n")

    alerts = 0
    modules = get_loaded_modules()
    logs = get_kernel_logs()

    if not modules:
        log.write(json.dumps({"event": "WARNING", "message": "lsmod returned nothing — cannot verify driver state"}) + "\n")
    elif "nvidia" not in modules and "nvidia_uvm" not in modules:
        alerts += 1
        log.write(json.dumps({
            "detector": "D90_GPU_DRIVER_UNLOADED",
            "severity": "CRITICAL",
            "loaded_modules": modules,
            "confidence": 0.8,
            "note": "NVIDIA driver modules missing from kernel — potential tampering or load failure"
        }) + "\n")

    for l in logs:
        if "error" in l.lower() or "fault" in l.lower():
            alerts += 1
            log.write(json.dumps({
                "detector": "D91_GPU_KERNEL_ERROR",
                "severity": "WARN",
                "log_line": l,
                "confidence": 0.6,
                "note": "GPU kernel error or fault detected in dmesg"
            }) + "\n")

    log.write(json.dumps({"event": "RUN_END", "alerts": alerts, "ts": now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 15: alerts={alerts}\nLog: {out}")


if __name__ == "__main__":
    main()
