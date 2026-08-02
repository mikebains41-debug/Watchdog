#!/usr/bin/env python3
"""
Watchdog — Module 8: CPU Thermal & IOMMU Scans
Scans dmesg for thermal throttle events and IOMMU/DMA errors.
"""
import subprocess, datetime, json

def scan_dmesg(keywords):
    try:
        out = subprocess.check_output(["dmesg", "-T"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        lines = out.splitlines()
        alerts = []
        for line in lines:
            for kw in keywords:
                if kw.lower() in line.lower():
                    alerts.append(line.strip())
                    break
        return alerts
    except:
        return []

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module8_thermal_iommu_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START", "module":"8_thermal_iommu"}) + "\n")

    alerts = 0
    thermal_events = scan_dmesg(["thermal", "throttle"])
    iommu_events = scan_dmesg(["DMAR", "IOMMU", "DMA error", "DMA fault"])

    for e in thermal_events:
        alerts += 1
        log.write(json.dumps({
            "detector":"D64_CPU_THERMAL_STRESS",
            "severity":"WARN",
            "log_line":e,
            "confidence":0.6,
            "note":"Kernel thermal throttle event detected"
        }) + "\n")

    for e in iommu_events:
        alerts += 1
        log.write(json.dumps({
            "detector":"D59_IOMMU_ERROR",
            "severity":"WARN",
            "log_line":e,
            "confidence":0.5,
            "note":"IOMMU/DMA remapping error detected"
        }) + "\n")

    log.write(json.dumps({"event":"RUN_END","alerts":alerts}) + "\n")
    log.close()
    print(f"Done. Module 8: alerts={alerts}\nLog: {out}")

if __name__ == "__main__":
    main()
