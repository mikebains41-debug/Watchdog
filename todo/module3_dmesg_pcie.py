#!/usr/bin/env python3
"""
Watchdog — Module 3: dmesg + PCIe source
Detects hardware faults and PCIe anomalies.

FIXED: get_lspci() previously used
  `if "LnkSta:" in l and "NVIDIA" in lines[i-1] if i > 0 else False`
which parses as `(A and B) if C else D` due to Python operator precedence —
not the intended "require NVIDIA device on the preceding line" check — and
also assumed the device name always sits exactly one line above LnkSta,
which lspci -vvv doesn't guarantee. Rewritten to track the current PCI
device block explicitly and only evaluate LnkSta lines within an NVIDIA
device's block.
"""
import os, subprocess, time, datetime, json, re
from collections import deque

XID_LOG_MAX = 20
LAST_XIDS = deque(maxlen=XID_LOG_MAX)
DURATION_S = 120


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_dmesg():
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        return out.strip().splitlines()
    except Exception:
        return []


def get_lspci_nvidia_linkspeed():
    """Return the first LnkSta GT/s value found inside an NVIDIA device block, or None."""
    try:
        out = subprocess.check_output(["lspci", "-vvv"], text=True, timeout=5, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    lines = out.strip().splitlines()
    in_nvidia_block = False
    for l in lines:
        # New device header lines start at column 0, e.g. "3b:00.0 3D controller: NVIDIA Corporation ..."
        if l and not l.startswith((" ", "\t")):
            in_nvidia_block = "NVIDIA" in l
            continue
        if in_nvidia_block and "LnkSta:" in l:
            m = re.search(r'(\d+\.?\d*)\s*GT/s', l)
            if m:
                return float(m.group(1))
    return None


def scan_xid(lines):
    alerts = []
    for l in lines:
        if "Xid" in l and "GPU" in l and l.strip() not in LAST_XIDS:
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
    log.write(json.dumps({"event": "RUN_START", "module": "3_dmesg", "ts": now_iso()}) + "\n")

    start = time.time()
    while time.time() < start + DURATION_S:
        samples += 1
        lines = get_dmesg()
        xid = scan_xid(lines)
        pcie = scan_pcie(lines)

        for x in xid:
            alerts += 1
            log.write(json.dumps({
                "detector": "D70_XID_ERROR",
                "severity": "CRITICAL",
                "log": x,
                "confidence": 0.9,
                "note": "GPU hardware fault event detected"
            }) + "\n")

        for p in pcie:
            alerts += 1
            log.write(json.dumps({
                "detector": "D32_PCIE_RESET",
                "severity": "WARN",
                "log": p,
                "confidence": 0.7,
                "note": "GPU PCIe reset or unbind detected"
            }) + "\n")

        speed = get_lspci_nvidia_linkspeed()
        if speed is not None and speed < 8.0:
            alerts += 1
            log.write(json.dumps({
                "detector": "D37_PCIE_LANE_SPEED",
                "severity": "WARN",
                "link_speed_gts": speed,
                "confidence": 0.6,
                "note": "PCIe link speed degraded below Gen4"
            }) + "\n")

        time.sleep(1)

    log.write(json.dumps({"event": "RUN_END", "samples": samples, "alerts": alerts, "ts": now_iso()}) + "\n")
    log.close()
    print(f"Done. Module 3: samples={samples}, alerts={alerts}\nLog: {out}")


if __name__ == "__main__":
    main()
