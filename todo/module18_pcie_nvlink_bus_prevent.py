#!/usr/bin/env python3
"""
Watchdog — Module 18: PCIe / NVLink Bus Prevention
Combines:
- pcie_bus_snoop_block.py (unbind on IOMMU/DMA fault)
- nvlink_sidechannel_blind.py (drop to Gen1 on spike)
- pcie_speed_check_guard.py (renegotiate on link degradation)
"""
import subprocess, time, datetime, json, re

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def check_dmesg_for_iommu():
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return "DMAR" in out or "IOMMU" in out
    except:
        return False

def unbind_pcie():
    try:
        subprocess.check_output(["echo", "1", ">", "/sys/bus/pci/devices/0000:00:00.0/remove"], shell=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def get_nvlink_bw():
    try:
        out = subprocess.check_output(["nvidia-smi", "nvlink", "-c"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        total = 0
        for line in out.splitlines():
            if "Bandwidth" in line:
                for token in line.split():
                    if token.isdigit():
                        total += int(token)
        return total
    except:
        return 0

def set_nvlink_gen1():
    try:
        subprocess.check_output(["nvidia-smi", "nvlink", "-s", "1"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def get_pcie_speed():
    try:
        out = subprocess.check_output(["lspci", "-vvv"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "LnkSta:" in line:
                match = re.search(r'(\d+\.?\d*) GT/s', line)
                if match:
                    return float(match.group(1))
        return None
    except:
        return None

def renegotiate_pcie():
    try:
        subprocess.check_output(["echo", "1", ">", "/sys/bus/pci/devices/0000:00:00.0/reset"], shell=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = f"module18_pcie_nvlink_bus_prevent_{stamp}.jsonl"
    log = open(out, "a")
    log.write(json.dumps({"event":"RUN_START","module":"18_pcie_nvlink_bus","ts":now_iso()}) + "\n")

    prev_bw = get_nvlink_bw()
    while True:
        if check_dmesg_for_iommu():
            if unbind_pcie():
                log.write(json.dumps({
                    "event":"PCIe_UNBOUND",
                    "action":"unbind 30s",
                    "reason":"IOMMU/DMA fault"
                }) + "\n")
                time.sleep(30)
                log.write(json.dumps({"event":"PCIe_REBOUND"}) + "\n")

        bw = get_nvlink_bw()
        if prev_bw and bw > prev_bw * 10:
            if set_nvlink_gen1():
                log.write(json.dumps({
                    "event":"NVLINK_DROPPED_TO_GEN1",
                    "bw":bw,
                    "action":"nvlink -s 1"
                }) + "\n")
        prev_bw = bw

        speed = get_pcie_speed()
        if speed and speed < 8.0:
            if renegotiate_pcie():
                log.write(json.dumps({
                    "event":"PCIe_RENEGOTIATE",
                    "speed":speed,
                    "action":"pcie reset"
                }) + "\n")
        time.sleep(5)

if __name__ == "__main__":
    main()
