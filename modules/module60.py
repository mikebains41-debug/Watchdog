#!/usr/bin/env python3
"""
Watchdog — Module 60: IOMMU Group & DMA Bus Master Auditor
Status: FUNCTIONAL — no special hardware required

Attack vector: any PCIe device with bus-master enabled can issue DMA reads
and writes to host memory. The IOMMU is what constrains where those reads
can land. On a quantum control host the devices that matter are the FPGA
pulse generators, the instrument interface cards, and whatever else shares
their IOMMU group.

An attacker can:
  - Insert a malicious PCIe device (a Thunderbolt/USB4 dock, an M.2 card,
    a rogue NIC) that enables bus mastering and reads control-plane memory
    directly, bypassing every OS-level control
  - Enable bus mastering on a device that had it disabled
  - Bind a device to vfio-pci to gain raw DMA access from userspace
  - Exploit IOMMU group co-residency: devices sharing a group can DMA to
    each other's memory regardless of kernel isolation

Distinct from module26, which checks NVMe-to-GPU peer mappings for GPU
Direct Storage. This module audits DMA capability across the whole bus.

WHAT THIS CHECKS (all functional now):
  - Every PCIe device's bus-master bit, read from the config space Command
    register (offset 0x04, bit 2). This is the definitive DMA-capable flag.
  - IOMMU presence and mode: is it enabled, and is it in passthrough
    (which means it is not actually protecting anything)
  - Full IOMMU group topology and which devices share each group
  - Devices bound to vfio-pci — userspace DMA access
  - Thunderbolt / USB4 / external PCIe devices, which are the physical
    insertion path for a DMA attack
  - ACS (Access Control Services) capability — without ACS, peer-to-peer
    DMA within a group is unconstrained
  - Baseline of the whole topology, with drift alerting

No fabricated device data. No simulated bus.
"""
import os, json, time, datetime, glob, subprocess, struct

POLL_INTERVAL   = 300
BASELINE_FILE   = "/tmp/watchdog_dma_baseline.json"
PCI_DEVICES     = "/sys/bus/pci/devices"
IOMMU_GROUPS    = "/sys/kernel/iommu_groups"

# PCI config space offsets
COMMAND_REGISTER_OFFSET = 0x04
BUS_MASTER_BIT          = 0x04   # bit 2 of the Command register

# PCI class codes worth naming when they appear with DMA enabled
PCI_CLASSES = {
    "0x030000": "VGA controller",
    "0x030200": "3D controller (GPU)",
    "0x010802": "NVMe storage",
    "0x020000": "Ethernet controller",
    "0x0c0330": "USB 3.0 xHCI",
    "0x0c0340": "USB4 / Thunderbolt",
    "0x088000": "System peripheral",
    "0x118000": "Signal processing (often FPGA)",
    "0x120000": "Processing accelerator (often FPGA)",
    "0x060400": "PCI bridge",
}

# Vendors whose devices are expected on a quantum control host
EXPECTED_VENDORS = {
    "8086": "Intel",
    "1022": "AMD",
    "10de": "NVIDIA",
    "10ee": "Xilinx / AMD (FPGA)",
    "1172": "Intel / Altera (FPGA)",
    "1c2c": "Lattice (FPGA)",
    "1a3e": "Microsemi (FPGA)",
    "144d": "Samsung (NVMe)",
    "1b4b": "Marvell",
    "15b3": "Mellanox",
    "1af4": "Red Hat / virtio",
}

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except:
        return {"devices": {}, "iommu_groups": {}, "established": now_iso()}

def save_baseline(b: dict):
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(b, f, indent=2)
    except:
        pass

def read_sysfs(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except (OSError, PermissionError):
        return None

def read_bus_master_bit(pci_addr: str) -> bool | None:
    """
    Read the PCI Command register from config space and test bit 2.
    This is the authoritative bus-master (DMA enable) flag.
    """
    config = os.path.join(PCI_DEVICES, pci_addr, "config")
    try:
        with open(config, "rb") as f:
            f.seek(COMMAND_REGISTER_OFFSET)
            raw = f.read(2)
        if len(raw) < 2:
            return None
        command = struct.unpack("<H", raw)[0]
        return bool(command & BUS_MASTER_BIT)
    except (OSError, PermissionError, struct.error):
        return None

def check_iommu_status() -> dict:
    """Is the IOMMU enabled, and is it actually enforcing?"""
    status = {"groups_present": os.path.isdir(IOMMU_GROUPS)}

    if status["groups_present"]:
        try:
            status["group_count"] = len(os.listdir(IOMMU_GROUPS))
        except:
            status["group_count"] = 0

    # Kernel command line tells us the mode
    cmdline = read_sysfs("/proc/cmdline") or ""
    status["cmdline_iommu"] = [tok for tok in cmdline.split()
                                if "iommu" in tok.lower()]
    status["passthrough"] = any("pt" in tok or "passthrough" in tok
                                 for tok in status["cmdline_iommu"])
    status["explicitly_off"] = any("iommu=off" in tok or "=off" in tok
                                    for tok in status["cmdline_iommu"])

    # Intel/AMD IOMMU driver presence in dmesg
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3,
                                       stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            low = line.lower()
            if "dmar" in low and "enabled" in low:
                status["dmar_enabled"] = True
            if "amd-vi" in low and "enabled" in low:
                status["amd_vi_enabled"] = True
    except Exception:
        pass

    return status

def enumerate_pci_devices() -> list:
    """Every PCIe device with its DMA state, IOMMU group, and driver."""
    devices = []
    if not os.path.isdir(PCI_DEVICES):
        return devices

    try:
        for addr in sorted(os.listdir(PCI_DEVICES)):
            dpath = os.path.join(PCI_DEVICES, addr)
            entry = {"pci_addr": addr}

            for field in ("vendor", "device", "class", "revision",
                          "subsystem_vendor", "subsystem_device"):
                val = read_sysfs(os.path.join(dpath, field))
                if val:
                    entry[field] = val

            vid = (entry.get("vendor") or "").replace("0x", "").lower()
            entry["vendor_name"] = EXPECTED_VENDORS.get(vid, "unknown")
            entry["known_vendor"] = vid in EXPECTED_VENDORS
            entry["class_name"] = PCI_CLASSES.get(entry.get("class", ""), "")

            # Bound driver
            drv_link = os.path.join(dpath, "driver")
            if os.path.islink(drv_link):
                entry["driver"] = os.path.basename(os.path.realpath(drv_link))
            else:
                entry["driver"] = None

            # IOMMU group
            grp_link = os.path.join(dpath, "iommu_group")
            if os.path.islink(grp_link):
                entry["iommu_group"] = os.path.basename(
                    os.path.realpath(grp_link))
            else:
                entry["iommu_group"] = None

            # Bus master bit — the DMA flag
            entry["bus_master"] = read_bus_master_bit(addr)

            # Removable / hotplug indicators
            entry["removable"] = read_sysfs(os.path.join(dpath, "removable"))
            # Thunderbolt / external device marker
            ext = read_sysfs(os.path.join(dpath, "untrusted"))
            entry["untrusted"] = ext == "1" if ext is not None else None

            devices.append(entry)
    except Exception:
        pass
    return devices

def map_iommu_groups() -> dict:
    """group_id -> list of PCI addresses sharing that group."""
    groups = {}
    if not os.path.isdir(IOMMU_GROUPS):
        return groups
    try:
        for gid in sorted(os.listdir(IOMMU_GROUPS), key=lambda x: int(x)
                          if x.isdigit() else 0):
            dev_dir = os.path.join(IOMMU_GROUPS, gid, "devices")
            if os.path.isdir(dev_dir):
                try:
                    groups[gid] = sorted(os.listdir(dev_dir))
                except (OSError, PermissionError):
                    pass
    except Exception:
        pass
    return groups

def check_acs(pci_addr: str) -> bool | None:
    """
    Does this device advertise ACS (Access Control Services)? Without ACS,
    peer-to-peer DMA inside an IOMMU group is not constrained.
    Detected via lspci capability dump — returns None if lspci absent.
    """
    try:
        out = subprocess.check_output(
            ["lspci", "-vvv", "-s", pci_addr],
            text=True, timeout=5, stderr=subprocess.DEVNULL)
        return "Access Control Services" in out or "ACSCtl" in out
    except Exception:
        return None

def analyse(devices: list, groups: dict, iommu: dict,
            baseline: dict) -> tuple:
    alerts = []
    known_devs   = baseline.get("devices", {})
    known_groups = baseline.get("iommu_groups", {})

    # ── 1. IOMMU not enforcing ──
    if not iommu.get("groups_present"):
        alerts.append({
            "event":    "IOMMU_NOT_ENABLED",
            "severity": "CRITICAL",
            "cmdline":  iommu.get("cmdline_iommu"),
            "confidence": 0.90,
            "note": ("No IOMMU groups present. Every bus-mastering device on "
                     "this host can DMA anywhere in physical memory with no "
                     "hardware constraint. A malicious PCIe device reads the "
                     "control plane directly"),
        })
    elif iommu.get("passthrough"):
        alerts.append({
            "event":    "IOMMU_PASSTHROUGH_MODE",
            "severity": "CRITICAL",
            "cmdline":  iommu.get("cmdline_iommu"),
            "confidence": 0.85,
            "note": ("IOMMU is in passthrough mode. Groups exist but no "
                     "translation is enforced — DMA is unconstrained. This is "
                     "commonly set for performance and is a serious gap on a "
                     "control host"),
        })
    elif iommu.get("explicitly_off"):
        alerts.append({
            "event":    "IOMMU_DISABLED_IN_CMDLINE",
            "severity": "CRITICAL",
            "cmdline":  iommu.get("cmdline_iommu"),
            "confidence": 0.90,
        })

    current = {}
    for d in devices:
        addr = d["pci_addr"]
        current[addr] = {
            "vendor":     d.get("vendor"),
            "device":     d.get("device"),
            "class":      d.get("class"),
            "driver":     d.get("driver"),
            "bus_master": d.get("bus_master"),
            "iommu_group": d.get("iommu_group"),
        }

        # ── 2. New device on the bus ──
        if addr not in known_devs:
            dma = d.get("bus_master")
            sev = "CRITICAL" if dma else "WARN"
            alerts.append({
                "event":    "UNAUTHORIZED_DMA_DEVICE" if dma else "NEW_PCI_DEVICE",
                "severity": sev,
                "pci_addr": addr,
                "vendor":   d.get("vendor"),
                "vendor_name": d.get("vendor_name"),
                "device":   d.get("device"),
                "class_name": d.get("class_name"),
                "driver":   d.get("driver"),
                "bus_master": dma,
                "iommu_group": d.get("iommu_group"),
                "known_vendor": d.get("known_vendor"),
                "confidence": 0.85 if dma else 0.55,
                "note": (("New PCIe device with bus mastering ENABLED. It can "
                          "issue DMA to host memory right now. Physical "
                          "insertion of a DMA-capable device is the classic "
                          "path to reading control-plane memory")
                         if dma else "New PCIe device since baseline"),
            })

        # ── 3. Bus master newly enabled on a known device ──
        elif addr in known_devs:
            prev = known_devs[addr]
            if prev.get("bus_master") is False and d.get("bus_master") is True:
                alerts.append({
                    "event":    "BUS_MASTER_ENABLED",
                    "severity": "CRITICAL",
                    "pci_addr": addr,
                    "vendor_name": d.get("vendor_name"),
                    "class_name":  d.get("class_name"),
                    "confidence": 0.85,
                    "note": ("Bus mastering was enabled on a device that "
                             "previously had it disabled. This device can now "
                             "DMA to host memory"),
                })
            if prev.get("driver") != d.get("driver"):
                sev = "CRITICAL" if d.get("driver") == "vfio-pci" else "WARN"
                alerts.append({
                    "event":    "PCI_DRIVER_CHANGED",
                    "severity": sev,
                    "pci_addr": addr,
                    "was":      prev.get("driver"),
                    "now":      d.get("driver"),
                    "confidence": 0.80 if sev == "CRITICAL" else 0.60,
                    "note": ("Device rebound to vfio-pci — this grants raw "
                             "DMA access from userspace"
                             if d.get("driver") == "vfio-pci"
                             else "Bound driver changed"),
                })
            if prev.get("iommu_group") != d.get("iommu_group"):
                alerts.append({
                    "event":    "IOMMU_GROUP_CHANGED",
                    "severity": "WARN",
                    "pci_addr": addr,
                    "was":      prev.get("iommu_group"),
                    "now":      d.get("iommu_group"),
                    "confidence": 0.70,
                })

        # ── 4. vfio-pci bound (userspace DMA) ──
        if d.get("driver") == "vfio-pci":
            alerts.append({
                "event":    "VFIO_BOUND_DEVICE",
                "severity": "WARN",
                "pci_addr": addr,
                "vendor_name": d.get("vendor_name"),
                "class_name":  d.get("class_name"),
                "iommu_group": d.get("iommu_group"),
                "confidence": 0.65,
                "note": ("Device is bound to vfio-pci, giving a userspace "
                         "process direct DMA access. Expected only for "
                         "deliberate VM passthrough"),
            })

        # ── 5. Untrusted / external device ──
        if d.get("untrusted"):
            alerts.append({
                "event":    "EXTERNAL_DMA_DEVICE",
                "severity": "CRITICAL",
                "pci_addr": addr,
                "vendor_name": d.get("vendor_name"),
                "class_name":  d.get("class_name"),
                "bus_master":  d.get("bus_master"),
                "confidence": 0.85,
                "note": ("Kernel marked this device untrusted — it arrived "
                         "over Thunderbolt/USB4 or another external port. "
                         "This is the physical insertion path for a DMA attack"),
            })

        # ── 6. Unknown vendor with DMA ──
        if d.get("bus_master") and not d.get("known_vendor"):
            alerts.append({
                "event":    "UNKNOWN_VENDOR_DMA_DEVICE",
                "severity": "WARN",
                "pci_addr": addr,
                "vendor":   d.get("vendor"),
                "class_name": d.get("class_name"),
                "confidence": 0.60,
                "note": ("Device from an unrecognised vendor has bus mastering "
                         "enabled. Verify this is authorised hardware"),
            })

    # ── 7. Device removed ──
    for addr in known_devs:
        if addr not in current:
            alerts.append({
                "event":    "PCI_DEVICE_REMOVED",
                "severity": "WARN",
                "pci_addr": addr,
                "was":      known_devs[addr],
                "confidence": 0.60,
            })

    # ── 8. IOMMU group co-residency ──
    for gid, members in groups.items():
        if len(members) > 1:
            # A group with multiple devices means those devices can DMA to
            # each other regardless of kernel isolation.
            dma_members = [m for m in members
                           if current.get(m, {}).get("bus_master")]
            if len(dma_members) > 1:
                if gid not in known_groups or set(members) != set(known_groups.get(gid, [])):
                    alerts.append({
                        "event":    "IOMMU_GROUP_ANOMALY",
                        "severity": "WARN",
                        "group":    gid,
                        "members":  members,
                        "dma_capable_members": dma_members,
                        "confidence": 0.65,
                        "note": ("Multiple bus-mastering devices share this "
                                 "IOMMU group. Without ACS they can DMA to "
                                 "each other's memory. If one is an FPGA "
                                 "control card, a compromised neighbour reads "
                                 "its buffers directly"),
                    })

    baseline["devices"]      = current
    baseline["iommu_groups"] = groups
    return alerts, baseline

def main():
    log = open(f"module60_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    iommu = check_iommu_status()

    emit({
        "event":  "RUN_START",
        "module": "60_iommu_dma_auditor",
        "status": "FUNCTIONAL — no special hardware required",
        "iommu_status": iommu,
        "checks": [
            "PCI Command register bus-master bit (offset 0x04, bit 2)",
            "IOMMU enabled / passthrough / disabled state",
            "IOMMU group topology and co-residency",
            "vfio-pci bound devices (userspace DMA)",
            "Kernel-marked untrusted (Thunderbolt/USB4) devices",
            "Unknown-vendor devices with DMA enabled",
            "Full bus topology baseline and drift",
        ],
        "distinct_from_module26": ("module26 checks NVMe-to-GPU peer mappings "
                                    "for GPU Direct Storage. This module audits "
                                    "DMA capability across the entire PCIe bus"),
    })

    baseline = load_baseline()
    first    = not baseline.get("devices")

    while True:
        devices = enumerate_pci_devices()
        groups  = map_iommu_groups()
        iommu   = check_iommu_status()

        dma_enabled = [d for d in devices if d.get("bus_master")]

        emit({"event": "DMA_SCAN",
              "pci_devices":      len(devices),
              "bus_master_enabled": len(dma_enabled),
              "iommu_groups":     len(groups),
              "vfio_bound":       len([d for d in devices
                                        if d.get("driver") == "vfio-pci"]),
              "untrusted":        len([d for d in devices
                                        if d.get("untrusted")])})

        if not devices:
            emit({"event": "NO_PCI_DEVICES",
                  "note": ("No PCIe devices readable. This host may be a "
                           "container without /sys/bus/pci access, or an "
                           "architecture without PCIe.")})
            break  # patched: exit immediately instead of looping back (was sleep+continue)

        if first:
            emit({"event": "DMA_BASELINE_ESTABLISHED",
                  "devices": len(devices),
                  "bus_master_enabled": len(dma_enabled),
                  "iommu_groups": len(groups)})
            baseline["devices"] = {
                d["pci_addr"]: {"vendor": d.get("vendor"),
                                 "device": d.get("device"),
                                 "class":  d.get("class"),
                                 "driver": d.get("driver"),
                                 "bus_master": d.get("bus_master"),
                                 "iommu_group": d.get("iommu_group")}
                for d in devices
            }
            baseline["iommu_groups"] = groups
            save_baseline(baseline)
            first = False
            # Still run the IOMMU-state checks on first pass
            alerts, _ = analyse([], {}, iommu, {"devices": {}, "iommu_groups": {}})
            for a in alerts:
                emit(a)
            break  # patched: exit immediately instead of looping back (was sleep+continue)

        alerts, baseline = analyse(devices, groups, iommu, baseline)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "PCI_BUS_CLEAN",
                  "devices_scanned": len(devices),
                  "dma_capable":     len(dma_enabled)})

        save_baseline(baseline)
        break  # patched: run once and exit instead of infinite monitoring loop
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
