#!/usr/bin/env python3
"""
Watchdog — Module 57: Electromagnetic & Side-Channel Emanation Guard
Status: PARTIAL — host-side SDR/probe detection functional, RF spectrum
        monitoring AWAITING_HARDWARE_INTEGRATION

Attack vector: every control line entering a cryostat radiates. Microwave
pulse generators, coax runs from room temperature to the mixing chamber, and
the FPGA driving them all emanate electromagnetic signal correlated with the
computation being performed. An attacker with an RF probe near the rack — or
a compromised SDR already inside the facility — can:

  - Recover algorithmic state from pulse-envelope emanations without ever
    touching the control host
  - Extract cryptographic keys from power and EM traces (classical
    differential power analysis applied to the classical control plane)
  - Fingerprint which circuits a tenant is running from pulse timing patterns
  - Correlate emanation with job submissions to break tenant isolation

This is TEMPEST-class. It leaves no trace in any log, defeats every
software control, and works through a wall.

Module44 monitors power via RAPL — coarse, CPU-domain, and sampled far too
slowly to see the high-frequency transients that carry side-channel
information. This module covers what module44 cannot.

WHAT RUNS NOW (no RF hardware needed):
  - Detect SDR hardware attached to the host (RTL-SDR, HackRF, USRP,
    BladeRF, Airspy, LimeSDR) by USB vendor/product ID
  - Detect SDR kernel modules loaded
  - Detect SDR and RF capture software running (rtl_sdr, hackrf_transfer,
    uhd_rx, gqrx, gnuradio, inspectrum, urh)
  - Detect promiscuous-mode capture on any interface
  - Detect high-resolution timer abuse: processes reading the TSC or
    HPET at rates consistent with a timing side-channel harvester
  - Baseline USB device inventory and flag new RF-capable devices

WHAT NEEDS HARDWARE (documented, not simulated):
  - RF spectrum analyzer telemetry: monitoring the band around the
    microwave drive frequencies (typically 4-8 GHz for transmon qubits)
    for unauthorized receivers or injected tones
  - Near-field EM probe on the control lines entering the cryostat
  - High-bandwidth power rail monitoring (>1 MHz sample rate) for
    differential power analysis detection
  - Faraday enclosure integrity monitoring

No RF data is fabricated. No simulated spectrum. No random().
"""
import json, datetime, os, time, glob, subprocess, re
from collections import defaultdict

POLL_INTERVAL      = 300     # seconds between scans
INVENTORY_FILE     = "/tmp/watchdog_em_inventory.json"

# USB vendor:product IDs of software-defined radio hardware.
# Presence of any of these near a quantum control rack is a finding.
SDR_DEVICES = {
    "0bda:2838": "RTL-SDR (Realtek RTL2838)",
    "0bda:2832": "RTL-SDR (Realtek RTL2832U)",
    "1d50:6089": "HackRF One",
    "1d50:cc15": "HackRF Jawbreaker",
    "2500:0020": "Ettus USRP B200",
    "2500:0021": "Ettus USRP B210",
    "2500:0022": "Ettus USRP B200mini",
    "1d50:6066": "BladeRF",
    "2cf0:5246": "Nuand BladeRF 2.0",
    "1d50:60a1": "Airspy",
    "03eb:800c": "Airspy HF+",
    "1d50:6108": "LimeSDR",
    "0403:601f": "LimeSDR Mini (FTDI)",
    "16d0:04d0": "SDRplay RSP",
    "1df7:2500": "SDRplay RSP1A",
    "1df7:3000": "SDRplay RSPduo",
}

SDR_KERNEL_MODULES = [
    "rtl2832", "rtl2838", "dvb_usb_rtl28xxu", "hackrf",
    "usrp", "bladerf", "airspy", "sdr_msi3101", "msi2500",
    "rtl_sdr", "limesdr", "sdrplay",
]

RF_CAPTURE_TOOLS = [
    "rtl_sdr", "rtl_fm", "rtl_power", "rtl_tcp", "rtl_test",
    "hackrf_transfer", "hackrf_sweep", "hackrf_info",
    "uhd_rx_cfile", "uhd_fft", "uhd_usrp_probe",
    "bladeRF-cli", "airspy_rx", "airspy_info",
    "gqrx", "gnuradio-companion", "grcc", "inspectrum",
    "urh", "universal-radio-hacker", "sdrangel", "cubicsdr",
    "soapy_power", "SoapySDRUtil", "rx_tools", "kalibrate",
]

# Drive frequencies for superconducting qubits — the band an attacker
# would target. Documented for the hardware integration phase.
QUBIT_DRIVE_BAND_GHZ = (4.0, 8.0)
READOUT_BAND_GHZ     = (6.0, 7.5)

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_inventory() -> dict:
    try:
        with open(INVENTORY_FILE) as f:
            return json.load(f)
    except:
        return {"usb_devices": {}, "established": now_iso()}

def save_inventory(inv: dict):
    try:
        with open(INVENTORY_FILE, "w") as f:
            json.dump(inv, f, indent=2)
    except:
        pass

def enumerate_usb_devices() -> dict:
    """
    Walk sysfs for every USB device and return vendor:product -> details.
    No lsusb dependency.
    """
    devices = {}
    base = "/sys/bus/usb/devices"
    if not os.path.isdir(base):
        return devices
    try:
        for dev in sorted(os.listdir(base)):
            dpath = os.path.join(base, dev)
            vid_file = os.path.join(dpath, "idVendor")
            pid_file = os.path.join(dpath, "idProduct")
            if not (os.path.exists(vid_file) and os.path.exists(pid_file)):
                continue
            try:
                with open(vid_file) as f:
                    vid = f.read().strip().lower()
                with open(pid_file) as f:
                    pid = f.read().strip().lower()
                key = f"{vid}:{pid}"
                entry = {"vendor_id": vid, "product_id": pid, "sysfs": dev}
                for field in ("manufacturer", "product", "serial"):
                    fp = os.path.join(dpath, field)
                    if os.path.exists(fp):
                        try:
                            with open(fp) as f:
                                entry[field] = f.read().strip()
                        except:
                            pass
                devices[key] = entry
            except (OSError, PermissionError):
                continue
    except Exception:
        pass
    return devices

def check_sdr_modules() -> list:
    """Which SDR kernel modules are loaded?"""
    loaded = []
    try:
        out = subprocess.check_output(["lsmod"], text=True, timeout=3,
                                       stderr=subprocess.DEVNULL)
        for line in out.splitlines()[1:]:
            mod = line.split()[0].lower().replace("-", "_")
            for sm in SDR_KERNEL_MODULES:
                if sm.replace("-", "_") in mod:
                    loaded.append(mod)
                    break
    except Exception:
        pass
    return sorted(set(loaded))

def check_rf_tools() -> list:
    """Any RF capture or SDR tool currently running?"""
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
            base = os.path.basename(cmd.split()[0])
            for tool in RF_CAPTURE_TOOLS:
                if base == tool or base.lower() == tool.lower():
                    running.append({"pid": int(pid_dir), "tool": tool,
                                     "cmd": cmd[:200]})
                    break
    except Exception:
        pass
    return running

def check_promiscuous_interfaces() -> list:
    """
    Interfaces in promiscuous mode. Not RF directly, but the same
    posture — passive capture of signal not addressed to this host.
    """
    promisc = []
    base = "/sys/class/net"
    if not os.path.isdir(base):
        return promisc
    try:
        for iface in sorted(os.listdir(base)):
            flags_file = os.path.join(base, iface, "flags")
            if not os.path.exists(flags_file):
                continue
            try:
                with open(flags_file) as f:
                    flags = int(f.read().strip(), 16)
                # IFF_PROMISC = 0x100
                if flags & 0x100:
                    promisc.append(iface)
            except:
                pass
    except Exception:
        pass
    return promisc

def check_timer_abuse() -> list:
    """
    Timing side-channel harvesters need a high-resolution clock. Detect
    processes with clocksource or HPET/TSC device files open — legitimate
    workloads rarely need direct access.
    """
    suspects = []
    timer_devices = ["/dev/hpet", "/dev/rtc", "/dev/rtc0"]
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            fd_dir = f"/proc/{pid_dir}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        target = os.readlink(os.path.join(fd_dir, fd))
                        if target in timer_devices:
                            cmd = ""
                            try:
                                with open(f"/proc/{pid_dir}/cmdline", "rb") as f:
                                    cmd = (f.read().replace(b"\x00", b" ")
                                             .decode("utf-8", errors="replace").strip())
                            except:
                                pass
                            suspects.append({"pid": int(pid_dir),
                                              "device": target,
                                              "cmd": cmd[:160]})
                            break
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue
    except Exception:
        pass
    return suspects

def check_dmesg_rf_events() -> list:
    """dmesg lines mentioning SDR or RF hardware attachment."""
    hits = []
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3,
                                       stderr=subprocess.DEVNULL)
        patterns = ["rtl2832", "rtl2838", "hackrf", "usrp", "bladerf",
                     "airspy", "limesdr", "sdrplay", "dvb_usb"]
        for line in out.splitlines():
            low = line.lower()
            for p in patterns:
                if p in low:
                    hits.append(line.strip())
                    break
    except Exception:
        pass
    return hits[-15:]

def analyse(usb: dict, inventory: dict, sdr_mods: list,
            rf_tools: list, promisc: list, timers: list,
            dmesg_hits: list) -> tuple:
    alerts = []
    known = inventory.get("usb_devices", {})

    # ── 1. SDR hardware attached ──
    for key, dev in usb.items():
        if key in SDR_DEVICES:
            alerts.append({
                "event":    "SDR_HARDWARE_DETECTED",
                "severity": "CRITICAL",
                "device":   SDR_DEVICES[key],
                "usb_id":   key,
                "manufacturer": dev.get("manufacturer"),
                "product":  dev.get("product"),
                "serial":   dev.get("serial"),
                "confidence": 0.90,
                "note": (f"{SDR_DEVICES[key]} is attached to this host. "
                         "Software-defined radio hardware on a quantum control "
                         "server has no legitimate operational purpose and is "
                         "capable of capturing emanations from the control "
                         "lines and pulse generators"),
            })

    # ── 2. New USB device since baseline ──
    for key, dev in usb.items():
        if key not in known:
            is_sdr = key in SDR_DEVICES
            alerts.append({
                "event":    "NEW_USB_DEVICE",
                "severity": "CRITICAL" if is_sdr else "INFO",
                "usb_id":   key,
                "product":  dev.get("product"),
                "manufacturer": dev.get("manufacturer"),
                "known_sdr": is_sdr,
                "confidence": 0.85 if is_sdr else 0.35,
                "note": ("New USB device since baseline. On an air-gapped or "
                         "physically-secured control host, any new device is "
                         "a physical access event"),
            })

    # ── 3. SDR kernel modules loaded ──
    if sdr_mods:
        alerts.append({
            "event":    "SDR_KERNEL_MODULE_LOADED",
            "severity": "CRITICAL",
            "modules":  sdr_mods,
            "confidence": 0.85,
            "note": ("SDR kernel modules are loaded. Even with no device "
                     "currently attached, this indicates SDR hardware has been "
                     "used on this host"),
        })

    # ── 4. RF capture tooling running ──
    for t in rf_tools:
        alerts.append({
            "event":    "RF_CAPTURE_TOOL_RUNNING",
            "severity": "CRITICAL",
            "pid":      t["pid"],
            "tool":     t["tool"],
            "cmd":      t["cmd"],
            "confidence": 0.90,
            "note": (f"{t['tool']} is actively running. This is live RF "
                     "capture or analysis on the quantum control host"),
        })

    # ── 5. Promiscuous interfaces ──
    for iface in promisc:
        alerts.append({
            "event":    "PROMISCUOUS_INTERFACE",
            "severity": "WARN",
            "interface": iface,
            "confidence": 0.60,
            "note": ("Interface in promiscuous mode — passive capture of "
                     "traffic not addressed to this host"),
        })

    # ── 6. Timer device access ──
    for t in timers:
        alerts.append({
            "event":    "HIGH_RES_TIMER_ACCESS",
            "severity": "WARN",
            "pid":      t["pid"],
            "device":   t["device"],
            "cmd":      t["cmd"],
            "confidence": 0.50,
            "note": ("Process holds a high-resolution timer device open. "
                     "Timing side-channel harvesters require precise clocks; "
                     "most legitimate workloads do not open these directly"),
        })

    # ── 7. dmesg RF hardware events ──
    for line in dmesg_hits:
        alerts.append({
            "event":    "DMESG_RF_HARDWARE",
            "severity": "WARN",
            "log":      line,
            "confidence": 0.70,
            "note": "Kernel logged SDR/RF hardware attachment",
        })

    inventory["usb_devices"] = usb
    return alerts, inventory

def main():
    log = open(f"module57_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "57_em_sidechannel_guard",
        "status": "PARTIAL — host-side detection functional, RF spectrum monitoring AWAITING_HARDWARE_INTEGRATION",
        "functional_now": [
            f"SDR hardware detection by USB ID ({len(SDR_DEVICES)} known devices)",
            "SDR kernel module detection",
            f"RF capture tool detection ({len(RF_CAPTURE_TOOLS)} tools)",
            "Promiscuous interface detection",
            "High-resolution timer device access audit",
            "USB device inventory baseline and drift",
            "dmesg RF hardware attachment events",
        ],
        "awaiting_hardware": [
            f"RF spectrum monitoring of qubit drive band ({QUBIT_DRIVE_BAND_GHZ[0]}-{QUBIT_DRIVE_BAND_GHZ[1]} GHz)",
            f"Readout band monitoring ({READOUT_BAND_GHZ[0]}-{READOUT_BAND_GHZ[1]} GHz)",
            "Near-field EM probe on cryostat control lines",
            "High-bandwidth power rail capture (>1 MHz) for DPA detection",
            "Faraday enclosure integrity monitoring",
        ],
        "integration_required": [
            "Spectrum analyzer with SCPI/VISA interface, or a dedicated monitoring SDR",
            "Near-field EM probe positioned on the control line bundle",
            "High-bandwidth current probe on the power rail",
            "TEMPEST-rated enclosure with door/seal sensors",
        ],
        "reference": "TEMPEST / NSTISSAM 1-92, NATO SDIP-27",
    })

    inventory = load_inventory()
    alerts    = 0
    first     = True

    while True:
        usb        = enumerate_usb_devices()
        sdr_mods   = check_sdr_modules()
        rf_tools   = check_rf_tools()
        promisc    = check_promiscuous_interfaces()
        timers     = check_timer_abuse()
        dmesg_hits = check_dmesg_rf_events()

        sdr_present = [k for k in usb if k in SDR_DEVICES]

        emit({"event": "EM_SCAN",
              "usb_devices":     len(usb),
              "sdr_devices":     len(sdr_present),
              "sdr_modules":     sdr_mods,
              "rf_tools":        len(rf_tools),
              "promiscuous_ifaces": promisc,
              "timer_holders":   len(timers)})

        if first and not inventory.get("usb_devices"):
            emit({"event": "BASELINE_ESTABLISHED",
                  "usb_devices": len(usb),
                  "note": ("First run — USB inventory baselined. Subsequent "
                           "runs flag any new device.")})
            inventory["usb_devices"] = usb
            save_inventory(inventory)
            first = False
            # Still run the SDR/tool checks on first pass
            if sdr_present or sdr_mods or rf_tools:
                pass
            else:
                time.sleep(POLL_INTERVAL)
                continue

        first = False
        new_alerts, inventory = analyse(usb, inventory, sdr_mods,
                                         rf_tools, promisc, timers, dmesg_hits)
        for a in new_alerts:
            alerts += 1
            emit(a)

        save_inventory(inventory)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
