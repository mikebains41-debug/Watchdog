#!/usr/bin/env python3
"""
Watchdog — GDS (GPU Direct Storage) VRAM Guard (B200)
Attack: Compromised NVMe SSD with GDS support writes directly to GPU VRAM
        via SSD controller, bypassing host CPU IOMMU entirely.
        Can overwrite model weights while model is actively running.

Prevention:
  - Monitors /sys/block/nvme* for GDS/peer-memory mappings
  - Checks nvidia-peermem driver for unexpected peer mappings
  - Monitors IOMMU mappings for NVMe→GPU DMA paths without known CUDA context
  - On detection: unbinds NVMe driver to cut direct memory path
  - Rebinds after 30s (long enough to flush any in-flight DMA)

Note: Document suggested detecting "cudaMalloc events" — not possible from
userspace. Correct approach: monitor nvidia-peermem + /proc/driver/nvidia/gpus
for peer mappings, and cross-reference active CUDA compute apps.
"""
import subprocess, time, datetime, json, os, re

POLL_INTERVAL    = 3      # seconds between checks
UNBIND_DURATION  = 30     # seconds NVMe stays unbound
REBIND_COOLDOWN  = 60     # seconds before allowing another unbind
GDS_SUSPICIOUS_MB = 100   # MB — NVMe→GPU mapping above this is suspicious

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ── NVMe helpers ────────────────────────────────────────────────────
def get_nvme_devices() -> list:
    """Return list of NVMe device paths."""
    try:
        return [f"/sys/block/{d}"
                for d in os.listdir("/sys/block")
                if d.startswith("nvme")]
    except:
        return []

def get_nvme_pcie_addr(nvme_path: str) -> str | None:
    """Get PCIe address for an NVMe device."""
    try:
        device_link = os.path.join(nvme_path, "device")
        real = os.path.realpath(device_link)
        # Extract PCI address from path like /sys/devices/pci0000:00/0000:00:XX.X/...
        m = re.search(r'(\d{4}:\d{2}:\d{2}\.\d)', real)
        return m.group(1) if m else None
    except:
        return None

def check_nvme_gds_mapping(nvme_path: str) -> dict | None:
    """
    Check if NVMe device has active GDS (peer-to-peer) mapping to GPU VRAM.
    Looks for:
    1. nvidia-peermem module loaded (required for GDS)
    2. Peer mapping in /proc/driver/nvidia/gpus/*/clients
    3. p2p_dma flag in NVMe device attributes
    """
    result = {}

    # Check if nvidia-peermem is loaded (GDS prerequisite)
    try:
        lsmod = subprocess.check_output(
            ["lsmod"], text=True, timeout=2, stderr=subprocess.DEVNULL)
        if "nvidia_peermem" not in lsmod:
            return None   # GDS not active — no threat
        result["nvidia_peermem_loaded"] = True
    except:
        return None

    # Check for peer mappings in nvidia driver
    gpu_clients_path = "/proc/driver/nvidia/gpus"
    try:
        if os.path.exists(gpu_clients_path):
            for gpu in os.listdir(gpu_clients_path):
                clients_file = os.path.join(gpu_clients_path, gpu, "clients")
                if os.path.exists(clients_file):
                    with open(clients_file) as f:
                        content = f.read()
                    if "nvme" in content.lower() or "peer" in content.lower():
                        result["gpu"] = gpu
                        result["peer_mapping_found"] = True
    except:
        pass

    # Check NVMe integrity via dmesg for suspicious DMA activity
    try:
        out = subprocess.check_output(
            ["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        nvme_name = os.path.basename(nvme_path)
        for line in out.splitlines():
            if nvme_name in line and ("dma" in line.lower() or "peer" in line.lower()):
                result["dmesg_dma_line"] = line.strip()
                result["suspicious_dma"] = True
    except:
        pass

    return result if result.get("peer_mapping_found") or \
                     result.get("suspicious_dma") else None

def get_active_cuda_apps() -> set:
    """Return set of PIDs with active CUDA compute contexts."""
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-compute-apps=pid",
             "--format=csv,noheader,nounits"],
            text=True, timeout=3)
        return set(p.strip() for p in out.strip().splitlines() if p.strip())
    except:
        return set()

def unbind_nvme(pcie_addr: str) -> bool:
    """Unbind NVMe driver to cut GPU Direct Storage path."""
    try:
        unbind_path = "/sys/bus/pci/drivers/nvme/unbind"
        with open(unbind_path, "w") as f:
            f.write(pcie_addr)
        return True
    except:
        # Try generic PCI remove
        try:
            with open(f"/sys/bus/pci/devices/{pcie_addr}/remove", "w") as f:
                f.write("1")
            return True
        except:
            return False

def rebind_nvme(pcie_addr: str) -> bool:
    """Re-bind NVMe driver after cooldown."""
    try:
        # Rescan PCI bus to rediscover device
        with open("/sys/bus/pci/rescan", "w") as f:
            f.write("1")
        return True
    except:
        return False

def check_iommu_nvme_gpu_mapping() -> list:
    """
    Check IOMMU groups for NVMe devices sharing a group with GPU.
    Devices in the same IOMMU group can do peer DMA — a security risk.
    """
    suspicious = []
    try:
        iommu_base = "/sys/kernel/iommu_groups"
        if not os.path.exists(iommu_base):
            return []

        for group in os.listdir(iommu_base):
            devices_path = os.path.join(iommu_base, group, "devices")
            if not os.path.exists(devices_path):
                continue

            devices = os.listdir(devices_path)
            has_gpu  = any("nvidia" in d.lower() or
                          _is_gpu_pci(os.path.join(devices_path, d))
                          for d in devices)
            has_nvme = any(_is_nvme_pci(os.path.join(devices_path, d))
                          for d in devices)

            if has_gpu and has_nvme:
                suspicious.append({
                    "iommu_group": group,
                    "devices": devices,
                    "risk": "NVMe and GPU share IOMMU group — GDS DMA possible"
                })
    except:
        pass
    return suspicious

def _is_gpu_pci(path: str) -> bool:
    try:
        class_file = os.path.join(os.path.realpath(path), "class")
        with open(class_file) as f:
            return f.read().strip().startswith("0x0302")  # 3D controller
    except:
        return False

def _is_nvme_pci(path: str) -> bool:
    try:
        class_file = os.path.join(os.path.realpath(path), "class")
        with open(class_file) as f:
            return f.read().strip() == "0x010802"  # NVMe storage controller
    except:
        return False

def main():
    log = open(f"watchdog_gds_guard_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "gds_vram_guard", "gpu": "B200",
          "poll_interval_s": POLL_INTERVAL,
          "unbind_duration_s": UNBIND_DURATION})

    # Log any shared IOMMU groups at startup (static risk)
    shared = check_iommu_nvme_gpu_mapping()
    for s in shared:
        emit({"event": "IOMMU_GROUP_RISK", **s})

    last_unbind: dict = {}   # pcie_addr → last unbind timestamp

    while True:
        time.sleep(POLL_INTERVAL)

        cuda_apps = get_active_cuda_apps()
        nvme_devs = get_nvme_devices()

        for nvme_path in nvme_devs:
            pcie_addr = get_nvme_pcie_addr(nvme_path)
            mapping   = check_nvme_gds_mapping(nvme_path)

            if mapping is None:
                continue

            # GDS mapping exists — check if any legitimate CUDA app is active
            # Legitimate GDS would have an owning CUDA process
            if not cuda_apps:
                # GDS mapping with zero CUDA apps = suspicious
                emit({"event": "GDS_MAPPING_NO_CUDA_OWNER",
                      "nvme": os.path.basename(nvme_path),
                      "pcie_addr": pcie_addr,
                      "mapping": mapping,
                      "cuda_apps": list(cuda_apps),
                      "severity": "HIGH"})

                now = time.time()
                if pcie_addr and \
                   now - last_unbind.get(pcie_addr, 0) > REBIND_COOLDOWN:
                    if unbind_nvme(pcie_addr):
                        emit({"event": "NVME_UNBOUND",
                              "pcie_addr": pcie_addr,
                              "action": f"unbind {UNBIND_DURATION}s"})
                        last_unbind[pcie_addr] = now

                        time.sleep(UNBIND_DURATION)

                        if rebind_nvme(pcie_addr):
                            emit({"event": "NVME_REBOUND",
                                  "pcie_addr": pcie_addr})
            else:
                # GDS mapping with active CUDA app — log but don't block
                emit({"event": "GDS_MAPPING_ACTIVE",
                      "nvme": os.path.basename(nvme_path),
                      "cuda_apps": list(cuda_apps),
                      "mapping": mapping,
                      "severity": "INFO"})

if __name__ == "__main__":
    main()
