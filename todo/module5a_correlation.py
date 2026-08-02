#!/usr/bin/env python3
"""
Watchdog — Module 5a: Cross-source correlation
Fires when NVML power doesn't match system expectations.
"""
import time, datetime, json, subprocess

DURATION_S = 120


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def nvml_power():
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=power.draw", "--format=csv,noheader,nounits"],
            text=True, timeout=3
        )
        return float(out.strip())
    except Exception:
        return 0.0


def ebpftop_cpu():
    try:
        out = subprocess.check_output(["top", "-b", "-n", "1"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for l in out.splitlines():
            if "python3" in l or "watchdog" in l:
                parts = l.split()
                if len(parts) > 8 and "%" in parts[8]:
                    return float(parts[8].replace("%", ""))
        return 0.0
    except Exception:
        return 0.0


def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f'module5a_correlation_{stamp}.jsonl'
    log = open(out, 'a')
    alerts = 0
    samples = 0
    log.write(json.dumps({"event": "RUN_START", "module": "5a_correlation", "ts": now_iso()}) + "\n")

    start = time.time()
    while time.time() < start + DURATION_S:
        samples += 1
        pwr = nvml_power()
        cpu = ebpftop_cpu()
        if pwr > 400 and cpu < 5:
            alerts += 1
            log.write(json.dumps({
                "detector": "D26_CROSS_SOURCE_CORRELATION",
                "severity": "CRITICAL",
                "power_w": pwr,
                "cpu_pct": cpu,
                "confidence": 0.8,
                "note": "High GPU power but low CPU activity — possible telemetry tampering or hidden kernel"
            }) + "\n")
        time.sleep(1)

    log.write(json.dumps({"event": "RUN_END", "samples": samples, "alerts": alerts, "ts": now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 5a: samples={samples}, alerts={alerts}\nLog: {out}")


if __name__ == "__main__":
    main()
