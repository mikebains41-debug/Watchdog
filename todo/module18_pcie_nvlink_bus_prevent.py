#!/usr/bin/env python3
"""
Watchdog — Module 18: PCIe / NVLink Bus Prevention
"""
import subprocess, time, datetime, json, re, os

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def acquire_lock(event):
    try:
        fd = os.open(f"/tmp/watchdog_{event}.lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        return True
    except FileExistsError:
        return False

def release_lock(event):
    try:
        os.unlink(f"/tmp/watchdog_{event}.lock")
    except:
        pass

def check_dmesg_for_iommu():
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return "DMAR" in out or "IOMMU" in out
    except:
        return False

def unbind_pcie():
    try:
        with open("/sys/bus/pci/devices/0000:00:00.0/remove", "w") as f:
            f.write("1")
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

def disable_nvlink():
    try:
        subprocess.check_output(["nvidia-smi", "nvlink", "-d", "-i", "0"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def enable_nvlink():
    try:
        subprocess.check_output(["nvidia-smi", "nvlink", "-e", "-i", "0"], text=True, timeout=3, stderr=subprocess.DEVNULL)
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
        with open("/sys/bus/pci/devices/0000:00:00.0/reset", "w") as f:
            f.write("1")
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
            if acquire_lock("iommu"):
                if unbind_pcie():
                    log.write(json.dumps({
                        "event":"PCIe_UNBOUND",
                        "action":"unbind 30s",
                        "reason":"IOMMU/DMA fault"
                    }) + "\n")
                    time.sleep(30)
                    log.write(json.dumps({"event":"PCIe_REBOUND"}) + "\n")
                release_lock("iommu")

        bw = get_nvlink_bw()
        if prev_bw and bw > prev_bw * 10:
            if disable_nvlink():
                log.write(json.dumps({
                    "event":"NVLINK_DISABLED",
                    "bw":bw,
                    "action":"nvlink_disabled"
                }) + "\n")
                time.sleep(5)
                if enable_nvlink():
                    log.write(json.dumps({"event":"NVLINK_REENABLED"}) + "\n")
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
