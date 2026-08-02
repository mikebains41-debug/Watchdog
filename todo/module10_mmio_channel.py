#!/usr/bin/env python3
"""
Watchdog — Module 10: PCIe MMIO Covert Channel Logger
Logs PCIe link state and flags sudden speed drops that may indicate MMIO exfiltration.
"""
import subprocess, time, datetime, json, re

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_pcie_speed():
    try:
        out = subprocess.check_output(["nvidia-smi", "-q", "-d", "PCIe"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        lines = out.splitlines()
        for i, line in enumerate(lines):
            if "Link Speed" in line:
                match = re.search(r'(\d+\.?\d*) GT/s', line)
                if match:
                    return float(match.group(1))
                break
    except:
        pass
    return None

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module10_mmio_channel_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START", "module":"10_mmio", "ts":now_iso()}) + "\n")

    prev_speed = get_pcie_speed()
    prev_time = time.time()
    alerts = 0

    for _ in range(300):
        speed = get_pcie_speed()
        now = time.time()

        if prev_speed and speed:
            if speed < prev_speed * 0.8:  # 20% drop
                delta = (now - prev_time) * 1000.0
                alerts += 1
                log.write(json.dumps({
                    "detector":"MMIO_ANOMALY_DETECTED",
                    "severity":"INFO",
                    "old_speed":prev_speed,
                    "new_speed":speed,
                    "delta_ms":round(delta, 1),
                    "confidence":0.3,
                    "note":"PCIe link speed drop detected — possible MMIO exfiltration"
                }) + "\n")
        prev_speed = speed
        prev_time = now
        time.sleep(1.0)

    log.write(json.dumps({"event":"RUN_END","alerts":alerts,"ts":now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 10: alerts={alerts}\nLog: {out}")

if __name__ == "__main__":
    main()
