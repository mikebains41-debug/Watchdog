#!/usr/bin/env python3
"""
Watchdog — Module 56: FPGA Bitstream & JTAG Integrity Verifier
Status: PARTIAL — host-side checks functional, bitstream readback AWAITING_HARDWARE_INTEGRATION

Attack vector: module37 scans PCIe device IDs and confirms an FPGA control
card is present. It does not verify what logic that FPGA is actually running.

The microwave pulse generators that drive qubit gates are FPGA-defined. An
adversary who can reconfigure that logic — via JTAG, via a vulnerable DMA
channel, or by swapping the bitstream file loaded at boot — can subtly skew
pulse amplitude, phase, or duration. The result: gate errors injected at the
physical layer, invisible to every software-level calibration check, because
the calibration routine itself runs through the compromised pulse generator.

Partial reconfiguration makes this worse. Modern FPGAs can have one region
rewritten while the rest keeps running. No reboot, no driver reload, no
kernel event. The card never appears to change.

WHAT RUNS NOW (no hardware needed):
  - Locate every FPGA vendor device on the PCIe bus (Xilinx, Intel/Altera,
    Lattice, Microsemi) and record its full sysfs identity
  - SHA-256 hash every bitstream file found on disk in the standard firmware
    search paths, baseline them, and flag any change
  - Detect JTAG driver modules loaded in the kernel (xilinx_jtag, ftdi_sio
    bound to a JTAG interface, urjtag, openocd)
  - Detect JTAG/programming tools running (openocd, xsdb, vivado hw_server,
    quartus_pgm, UrJTAG)
  - Detect FPGA character devices being held open by unexpected processes
  - Monitor the Linux FPGA Manager framework (/sys/class/fpga_manager) for
    reconfiguration state changes — this is where partial reconfiguration
    shows up if the driver uses the standard framework
  - Watch dmesg for FPGA reconfiguration, DMA, and JTAG events

WHAT NEEDS HARDWARE (documented, not simulated):
  - Reading back the live configuration memory from the FPGA and comparing
    it against a golden bitstream hash. This is the only definitive check
    and it requires vendor tooling with device access.
  - Reading the FPGA's internal DNA / device identifier to confirm the
    physical part has not been swapped
  - Verifying bitstream authentication/encryption keys are actually enabled
    in the device's eFUSE configuration

No fabricated bitstream data. No simulated readback. No random().
"""
import json, datetime, os, time, hashlib, glob, subprocess, re

POLL_INTERVAL     = 600     # seconds between integrity scans
BASELINE_FILE     = "/tmp/watchdog_fpga_baseline.json"

FPGA_VENDOR_IDS = {
    "10ee": "Xilinx / AMD",
    "1172": "Intel / Altera",
    "1c2c": "Lattice Semiconductor",
    "1a3e": "Microsemi / Microchip",
    "12ba": "BittWare",
    "1204": "Lattice (legacy)",
}

# Where bitstreams commonly live
BITSTREAM_GLOBS = [
    "/lib/firmware/*.bit",
    "/lib/firmware/*.bin",
    "/lib/firmware/xilinx/*",
    "/lib/firmware/intel/*",
    "/usr/lib/firmware/*.bit",
    "/opt/*/firmware/*.bit",
    "/opt/*/bitstream/*",
    "/boot/*.bit",
]

# Kernel modules that expose JTAG or FPGA programming paths
JTAG_MODULES = [
    "xilinx_jtag", "xlnx_jtag", "jtag", "ftdi_sio",
    "usb_blaster", "altera_jtag", "urjtag", "ice40",
]

# Userspace tools capable of reprogramming an FPGA
PROGRAMMING_TOOLS = [
    "openocd", "xsdb", "hw_server", "vivado", "quartus_pgm",
    "jtagconfig", "urjtag", "jtag", "iceprog", "xc3sprog",
    "program_flash", "fpgautil",
]

FPGA_MANAGER_BASE = "/sys/class/fpga_manager"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except:
        return {"bitstreams": {}, "pcie_devices": {}, "established": now_iso()}

def save_baseline(b: dict):
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(b, f, indent=2)
    except:
        pass

def sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def scan_fpga_pcie() -> list:
    """Full sysfs identity of every FPGA device on the PCIe bus."""
    found = []
    base = "/sys/bus/pci/devices"
    if not os.path.isdir(base):
        return found
    try:
        for dev in sorted(os.listdir(base)):
            dpath = os.path.join(base, dev)
            try:
                with open(os.path.join(dpath, "vendor")) as f:
                    vendor = f.read().strip().replace("0x", "").lower()
                if vendor not in FPGA_VENDOR_IDS:
                    continue
                entry = {"pcie_addr": dev,
                         "vendor_id": vendor,
                         "vendor":    FPGA_VENDOR_IDS[vendor]}
                for field in ("device", "class", "revision",
                              "subsystem_vendor", "subsystem_device"):
                    fp = os.path.join(dpath, field)
                    if os.path.exists(fp):
                        try:
                            with open(fp) as f:
                                entry[field] = f.read().strip()
                        except:
                            pass
                # Which driver is bound?
                drv = os.path.join(dpath, "driver")
                if os.path.islink(drv):
                    entry["driver"] = os.path.basename(os.path.realpath(drv))
                found.append(entry)
            except (OSError, PermissionError):
                continue
    except Exception:
        pass
    return found

def scan_bitstream_files() -> dict:
    """Hash every bitstream file found in standard firmware paths."""
    result = {}
    for pattern in BITSTREAM_GLOBS:
        for path in glob.glob(pattern):
            if not os.path.isfile(path):
                continue
            h = sha256_file(path)
            if h:
                try:
                    st = os.stat(path)
                    result[path] = {"sha256": h,
                                     "size":   st.st_size,
                                     "mtime":  st.st_mtime}
                except:
                    result[path] = {"sha256": h}
    return result

def check_jtag_modules() -> list:
    """Which JTAG-capable kernel modules are loaded?"""
    loaded = []
    try:
        out = subprocess.check_output(["lsmod"], text=True, timeout=3,
                                       stderr=subprocess.DEVNULL)
        for line in out.splitlines()[1:]:
            mod = line.split()[0].lower()
            for jm in JTAG_MODULES:
                if jm in mod:
                    loaded.append(mod)
                    break
    except Exception:
        pass
    return sorted(set(loaded))

def check_programming_tools() -> list:
    """Any FPGA programming tool currently running?"""
    running = []
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            try:
                with open(f"/proc/{pid_dir}/cmdline", "rb") as f:
                    cmd = (f.read().replace(b"\x00", b" ")
                             .decode("utf-8", errors="replace").strip())
            except:
                continue
            if not cmd:
                continue
            base = os.path.basename(cmd.split()[0]).lower()
            for tool in PROGRAMMING_TOOLS:
                if tool == base or base.startswith(tool):
                    running.append({"pid": int(pid_dir), "tool": tool,
                                     "cmd": cmd[:200]})
                    break
    except Exception:
        pass
    return running

def check_fpga_manager() -> list:
    """
    Read the Linux FPGA Manager framework state. This is where partial
    reconfiguration surfaces on drivers that use the standard framework.
    """
    managers = []
    if not os.path.isdir(FPGA_MANAGER_BASE):
        return managers
    try:
        for mgr in sorted(os.listdir(FPGA_MANAGER_BASE)):
            mpath = os.path.join(FPGA_MANAGER_BASE, mgr)
            entry = {"manager": mgr}
            for field in ("name", "state", "status"):
                fp = os.path.join(mpath, field)
                if os.path.exists(fp):
                    try:
                        with open(fp) as f:
                            entry[field] = f.read().strip()
                    except:
                        pass
            managers.append(entry)
    except Exception:
        pass
    return managers

def check_dmesg_fpga_events() -> list:
    """Scan dmesg for FPGA reconfiguration, JTAG, and DMA events."""
    hits = []
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3,
                                       stderr=subprocess.DEVNULL)
        patterns = [
            r"fpga.*(program|reconfig|load|write)",
            r"jtag",
            r"xdma.*(error|fault|dma)",
            r"bitstream",
            r"partial.*reconfig",
        ]
        for line in out.splitlines():
            low = line.lower()
            for pat in patterns:
                if re.search(pat, low):
                    hits.append(line.strip())
                    break
    except Exception:
        pass
    return hits[-20:]

def find_fpga_device_holders() -> list:
    """Which processes hold FPGA character devices open?"""
    holders = []
    fpga_devs = []
    for pattern in ("/dev/xdma*", "/dev/xillybus*", "/dev/fpga*",
                    "/dev/uio*", "/dev/altera*"):
        fpga_devs.extend(glob.glob(pattern))

    if not fpga_devs:
        return holders

    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            fd_dir = f"/proc/{pid_dir}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        target = os.readlink(os.path.join(fd_dir, fd))
                        if target in fpga_devs:
                            cmd = ""
                            try:
                                with open(f"/proc/{pid_dir}/cmdline", "rb") as f:
                                    cmd = (f.read().replace(b"\x00", b" ")
                                             .decode("utf-8", errors="replace").strip())
                            except:
                                pass
                            holders.append({"pid": int(pid_dir),
                                             "device": target,
                                             "cmd": cmd[:160]})
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue
    except Exception:
        pass
    return holders

def analyse(pcie: list, bitstreams: dict, baseline: dict,
            jtag_mods: list, tools: list, managers: list,
            dmesg_hits: list, holders: list) -> tuple:
    alerts = []
    known_bs   = baseline.get("bitstreams", {})
    known_pcie = baseline.get("pcie_devices", {})

    # ── 1. Bitstream file changed ──
    for path, info in bitstreams.items():
        if path in known_bs:
            if info["sha256"] != known_bs[path].get("sha256"):
                alerts.append({
                    "event":    "FPGA_BITSTREAM_CHANGED",
                    "severity": "CRITICAL",
                    "path":     path,
                    "expected_sha256": known_bs[path].get("sha256", "")[:32] + "...",
                    "actual_sha256":   info["sha256"][:32] + "...",
                    "confidence": 0.95,
                    "note": ("Bitstream file on disk has changed since baseline. "
                             "The logic loaded into the pulse-generation FPGA "
                             "may no longer be the authorised design"),
                })
        else:
            alerts.append({
                "event":    "FPGA_BITSTREAM_NEW",
                "severity": "WARN",
                "path":     path,
                "sha256":   info["sha256"][:32] + "...",
                "confidence": 0.60,
                "note": "Bitstream file not present at baseline",
            })

    for path in known_bs:
        if path not in bitstreams:
            alerts.append({
                "event":    "FPGA_BITSTREAM_REMOVED",
                "severity": "WARN",
                "path":     path,
                "confidence": 0.60,
            })

    # ── 2. JTAG modules loaded ──
    if jtag_mods:
        alerts.append({
            "event":    "JTAG_MODULE_LOADED",
            "severity": "WARN",
            "modules":  jtag_mods,
            "confidence": 0.65,
            "note": ("JTAG-capable kernel modules are loaded. JTAG provides a "
                     "direct path to reprogram FPGA configuration memory, "
                     "bypassing every software-level check. On a production "
                     "control host these should not normally be present"),
        })

    # ── 3. Programming tools running ──
    for t in tools:
        alerts.append({
            "event":    "FPGA_PROGRAMMING_TOOL_RUNNING",
            "severity": "CRITICAL",
            "pid":      t["pid"],
            "tool":     t["tool"],
            "cmd":      t["cmd"],
            "confidence": 0.85,
            "note": (f"{t['tool']} is running. This tool can rewrite FPGA "
                     "configuration memory. Unless a scheduled maintenance "
                     "reflash is in progress, this is an active reconfiguration "
                     "attempt"),
        })

    # ── 4. FPGA Manager state ──
    for m in managers:
        state = (m.get("state") or "").lower()
        if state and state not in ("operating", "unknown", ""):
            sev = "CRITICAL" if any(k in state for k in
                                     ("write", "program", "load", "reset")) else "INFO"
            alerts.append({
                "event":    "FPGA_MANAGER_STATE",
                "severity": sev,
                "manager":  m.get("manager"),
                "name":     m.get("name"),
                "state":    m.get("state"),
                "confidence": 0.75 if sev == "CRITICAL" else 0.40,
                "note": ("FPGA Manager reports a non-operating state — "
                         "reconfiguration may be in progress"),
            })

    # ── 5. PCIe device changed ──
    current = {d["pcie_addr"]: d for d in pcie}
    for addr, dev in current.items():
        if addr in known_pcie:
            prev = known_pcie[addr]
            for field in ("device", "revision", "subsystem_device", "driver"):
                if prev.get(field) and dev.get(field) and prev[field] != dev[field]:
                    alerts.append({
                        "event":    "FPGA_PCIE_IDENTITY_CHANGED",
                        "severity": "CRITICAL",
                        "pcie_addr": addr,
                        "field":     field,
                        "was":       prev[field],
                        "now":       dev[field],
                        "confidence": 0.85,
                        "note": ("FPGA PCIe identity changed. Either the card "
                                 "was physically replaced, or its configuration "
                                 "was rewritten to present differently"),
                    })
        else:
            alerts.append({
                "event":    "FPGA_PCIE_NEW_DEVICE",
                "severity": "WARN",
                "pcie_addr": addr,
                "device":   dev,
                "confidence": 0.60,
            })

    for addr in known_pcie:
        if addr not in current:
            alerts.append({
                "event":    "FPGA_PCIE_DEVICE_LOST",
                "severity": "CRITICAL",
                "pcie_addr": addr,
                "confidence": 0.80,
                "note": ("FPGA control card present at baseline is gone from "
                         "the PCIe bus. Card removed, unbound, or hidden"),
            })

    # ── 6. dmesg events ──
    for line in dmesg_hits:
        low = line.lower()
        if any(k in low for k in ("program", "reconfig", "bitstream", "jtag")):
            alerts.append({
                "event":    "DMESG_FPGA_EVENT",
                "severity": "WARN",
                "log":      line,
                "confidence": 0.55,
            })

    # ── 7. Unexpected device holders ──
    if len(holders) > 1:
        alerts.append({
            "event":    "FPGA_DEVICE_MULTI_HOLDER",
            "severity": "WARN",
            "holders":  holders,
            "confidence": 0.60,
            "note": ("Multiple processes hold FPGA character devices open. "
                     "Verify each is an authorised control daemon"),
        })

    baseline["bitstreams"]   = bitstreams
    baseline["pcie_devices"] = current
    return alerts, baseline

def main():
    log = open(f"module56_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "56_fpga_bitstream_jtag",
        "status": "PARTIAL — host-side checks functional, live bitstream readback AWAITING_HARDWARE_INTEGRATION",
        "functional_now": [
            "FPGA PCIe device identity baseline and drift detection",
            "SHA-256 hashing of every bitstream file on disk",
            "JTAG kernel module detection",
            "FPGA programming tool detection (openocd, vivado, quartus_pgm, xsdb)",
            "Linux FPGA Manager framework state monitoring",
            "dmesg reconfiguration / JTAG / DMA event scanning",
            "FPGA character device holder audit",
        ],
        "awaiting_hardware": [
            "Live configuration memory readback vs golden bitstream hash",
            "FPGA device DNA / unique ID verification (detects part swap)",
            "eFUSE bitstream authentication key verification",
            "Partial reconfiguration region-level integrity",
        ],
        "integration_required": [
            "Vendor tooling with device access (Vivado hw_server, Quartus, openocd)",
            "A golden bitstream reference hash from the authorised build",
            "Read access to /dev/xdma* or vendor FPGA character device",
        ],
    })

    baseline = load_baseline()
    alerts   = 0
    first    = True

    while True:
        pcie       = scan_fpga_pcie()
        bitstreams = scan_bitstream_files()
        jtag_mods  = check_jtag_modules()
        tools      = check_programming_tools()
        managers   = check_fpga_manager()
        dmesg_hits = check_dmesg_fpga_events()
        holders    = find_fpga_device_holders()

        emit({"event": "FPGA_SCAN",
              "pcie_devices":     len(pcie),
              "bitstream_files":  len(bitstreams),
              "jtag_modules":     jtag_mods,
              "programming_tools": len(tools),
              "fpga_managers":    len(managers),
              "device_holders":   len(holders)})

        if not pcie:
            emit({"event": "NO_FPGA_DEVICES",
                  "note": ("No FPGA vendor devices found on the PCIe bus. "
                           "Either this is not a quantum control host, or the "
                           "pulse generator connects over a non-PCIe interface "
                           "(Ethernet, USB) requiring hardware integration.")})

        if first and not baseline.get("bitstreams"):
            emit({"event": "BASELINE_ESTABLISHED",
                  "bitstreams": len(bitstreams),
                  "pcie_devices": len(pcie),
                  "note": ("First run — baseline recorded. Subsequent runs will "
                           "flag any change against this snapshot.")})
            baseline["bitstreams"]   = bitstreams
            baseline["pcie_devices"] = {d["pcie_addr"]: d for d in pcie}
            save_baseline(baseline)
            first = False
            time.sleep(POLL_INTERVAL)
            continue

        first = False
        new_alerts, baseline = analyse(pcie, bitstreams, baseline,
                                        jtag_mods, tools, managers,
                                        dmesg_hits, holders)
        for a in new_alerts:
            alerts += 1
            emit(a)

        save_baseline(baseline)
        break  # patched: run once and exit instead of infinite monitoring loop
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
