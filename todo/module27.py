#!/usr/bin/env python3
"""
Watchdog — Module 27: VFIO Hypervisor Escape Prevention (B200)
Attack: Attacker uses vfio-pci driver to map GPU MMIO registers directly into
        guest VM address space, then DMA-reads host kernel memory out of hypervisor.
Prevention:
  - Monitors dmesg for vfio-pci DMA mapping failures
  - >3 failures in 60s → rmmod vfio-pci + rebind GPU to nvidia driver
  - Deduplicates dmesg lines (dmesg accumulates, same line appears repeatedly)
"""
import subprocess, time, datetime, json, os
from collections import deque

FAILURE_THRESHOLD = 3      # failures before action
FAILURE_WINDOW    = 60     # seconds
REBIND_WAIT       = 10     # seconds before rebinding nvidia
POLL_INTERVAL     = 2      # seconds

VFIO_ERROR_PATTERNS = [
    "vfio-pci",
    "DMA mapping failed",
    "vfio: IOMMU",
    "vfio: group",
    "vfio_pci",
]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def get_gpu_pcie_addr() -> str:
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=pci.bus_id",
             "--format=csv,noheader,nounits"],
            text=True, timeout=3)
        return out.strip().lower().replace("00000000:", "0000:")
    except:
        return "0000:00:00.0"

def scan_dmesg_vfio() -> list:
    try:
        out = subprocess.check_output(
            ["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        hits = []
        for line in out.splitlines():
            if any(p.lower() in line.lower() for p in VFIO_ERROR_PATTERNS):
                if "error" in line.lower() or "fail" in line.lower() \
                   or "deny" in line.lower():
                    hits.append(line.strip())
        return hits
    except:
        return []

def vfio_loaded() -> bool:
    try:
        out = subprocess.check_output(
            ["lsmod"], text=True, timeout=2, stderr=subprocess.DEVNULL)
        return "vfio_pci" in out or "vfio-pci" in out
    except:
        return False

def rmmod_vfio() -> bool:
    try:
        subprocess.check_output(
            ["rmmod", "vfio_pci"],
            timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def rebind_nvidia(pcie_addr: str) -> bool:
    """Rebind GPU from vfio-pci back to nvidia driver."""
    try:
        # Override driver
        override_path = f"/sys/bus/pci/devices/{pcie_addr}/driver_override"
        with open(override_path, "w") as f:
            f.write("nvidia")
        # Trigger probe
        with open("/sys/bus/pci/drivers_probe", "w") as f:
            f.write(pcie_addr)
        return True
    except:
        try:
            # Fallback: modprobe nvidia
            subprocess.check_output(
                ["modprobe", "nvidia"],
                timeout=5, stderr=subprocess.DEVNULL)
            return True
        except:
            return False

def main():
    pcie_addr = get_gpu_pcie_addr()
    log = open(f"module27_vfio_guard_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "27_vfio_guard", "gpu": "B200",
          "pcie_addr": pcie_addr, "threshold": FAILURE_THRESHOLD,
          "window_s": FAILURE_WINDOW})

    seen_lines   = set()
    event_window = deque()   # (line, timestamp)
    last_action  = 0.0

    while True:
        now  = time.time()
        hits = scan_dmesg_vfio()

        for line in hits:
            if line not in seen_lines:
                seen_lines.add(line)
                event_window.append((line, now))
                emit({"event": "VFIO_ERROR_DETECTED", "log": line})

        # Purge outside window
        while event_window and (now - event_window[0][1]) > FAILURE_WINDOW:
            event_window.popleft()

        if len(event_window) >= FAILURE_THRESHOLD and \
           now - last_action > FAILURE_WINDOW:
            last_action = now
            emit({"event": "VFIO_ATTACK_THRESHOLD_HIT",
                  "count": len(event_window),
                  "window_s": FAILURE_WINDOW})

            if vfio_loaded():
                if rmmod_vfio():
                    emit({"event": "VFIO_DRIVER_REMOVED",
                          "action": "rmmod vfio_pci"})
                    time.sleep(REBIND_WAIT)
                    if rebind_nvidia(pcie_addr):
                        emit({"event": "NVIDIA_DRIVER_REBOUND",
                              "pcie_addr": pcie_addr})
            else:
                emit({"event": "VFIO_NOT_LOADED",
                      "note": "vfio_pci not in lsmod — errors may be residual"})

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
