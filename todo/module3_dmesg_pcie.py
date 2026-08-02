#!/usr/bin/env python3
"""
Watchdog — Module 3: dmesg + PCIe source
Detects hardware faults and PCIe anomalies.
"""
import os, subprocess, time, datetime, json, re
from collections import deque

XID_LOG_MAX = 20
LAST_XIDS = deque(maxlen=XID_LOG_MAX)

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_dmesg():
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        return out.strip().splitlines()
    except:
        return []

def get_lspci():
    try:
        out = subprocess.check_output(["lspci", "-vvv"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        lines = out.strip().splitlines()
        for i, l in enumerate(lines):
            if "LnkSta:" in l and "NVIDIA" in lines[i-1] if i > 0 else False:
                return l.strip()
        return None
    except:
        return None

def scan_xid(lines):
    alerts = []
    for l in lines:
        if "Xid" in l and "GPU" in l and "Xid" not in ''.join(LAST_XIDS):
            alerts.append(l.strip())
            LAST_XIDS.append(l.strip())
    return alerts

def scan_pcie(lines):
    alerts = []
    for l in lines:
        if "pci" in l.lower() and "reset" in l.lower() and "GPU" in l:
            alerts.append(l.strip())
    return alerts

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f'module3_dmesg_{stamp}.jsonl'
    log = open(out, 'a')
    alerts = 0
    samples = 0
    log.write(json.dumps({"event":"RUN_START","module":"3_dmesg","ts":now_iso()}) + "\n")

    start = time.time()
    while time.time() < start + 120:
        samples += 1
        lines = get_dmesg()
        xid = scan_xid(lines)
        pcie = scan_pcie(lines)

        if xid:
            for x in xid:
                alerts += 1
                log.write(json.dumps({
                    "detector":"D7_XID_ERROR",
                    "severity":"CRITICAL",
                    "log":x,
                    "confidence":0.9,
                    "note":"GPU hardware fault event detected"
                }) + "\n")

        if pcie:
            for p in pcie:
                alerts += 1
                log.write(json.dumps({
                    "detector":"D32_PCIE_RESET",
                    "severity":"WARN",
                    "log":p,
                    "confidence":0.7,
                    "note":"GPU PCIe reset or unbind detected"
                }) + "\n")

        link = get_lspci()
        if link:
            if "LnkSta:" in link:
                m = re.search(r'LnkSta:\s+(\d+\.?\d*)GT/s', link)
                if m and float(m.group(1)) < 8.0:
                    alerts += 1
                    log.write(json.dumps({
                        "detector":"D37_PCIE_LANE_SPEED",
                        "severity":"WARN",
                        "link_speed":m.group(1),
                        "confidence":0.6,
                        "note":"PCIe link speed degraded below Gen4"
                    }) + "\n")
        time.sleep(1)

    log.write(json.dumps({"event":"RUN_END","samples":samples,"alerts":alerts,"ts":now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 3: samples={samples}, alerts={alerts}\nLog: {out}")

if __name__ == "__main__":
    main()
