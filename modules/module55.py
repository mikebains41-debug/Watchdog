#!/usr/bin/env python3
"""
Watchdog — Module 55: Cryogenic Instrument Bus Integrity Monitor
Status: PARTIAL — bus enumeration works now, sensor validation AWAITING_HARDWARE_INTEGRATION

Attack vector: cryogenic lab instruments — Lakeshore 370/372 temperature
controllers, Oxford MercuryiTC, Bluefors LD controllers, Pfeiffer MaxiGauge —
communicate over RS-232, GPIB (IEEE-488), USB-serial, or Modbus/TCP. None of
these protocols authenticate. They were designed for a trusted bench, not a
multi-tenant facility.

An attacker with host-level access to the control server can:
  - Open the serial device and inject fabricated sensor responses, so the
    control system reads 15 mK while the mixing chamber slowly warms and
    coherence quietly dies
  - Replay a recorded "everything normal" response indefinitely
  - Man-in-the-middle the bus, passing real reads through while suppressing
    alarm thresholds
  - Issue setpoint changes the operator never requested

None of this touches the QPU API. Nothing at the software layer sees it.

WHAT RUNS NOW (no hardware needed):
  - Enumerate every serial, USB-serial, and GPIB device present on the host
  - Identify which processes hold those devices open (lsof / /proc/*/fd)
  - Flag multiple processes with the same instrument device open — the
    signature of a MITM shim sitting between the controller and the daemon
  - Baseline device inventory and flag new instrument devices appearing
  - Check device permissions — world-writable instrument devices are a gap

WHAT NEEDS HARDWARE (documented, not simulated):
  - Cross-validating a controller's reported temperature against an
    independent out-of-band sensor
  - Challenge-response probing: issue a benign query with a known-variable
    answer (e.g. instrument uptime) and verify the response actually changes.
    A replay shim returns a frozen value.
  - Verifying setpoint reads match setpoint writes

No sensor code. No simulated readings. No random().
"""
import json, datetime, os, time, subprocess, glob, stat, hashlib
from collections import defaultdict

POLL_INTERVAL       = 300     # seconds between bus scans
INVENTORY_FILE      = "/tmp/watchdog_cryo_bus_inventory.json"
MULTI_HOLDER_LIMIT  = 1       # >1 process holding an instrument device = MITM signal

# Device path patterns for lab instrument buses
SERIAL_GLOBS = [
    "/dev/ttyUSB*",     # USB-serial adapters — most common for lab gear
    "/dev/ttyS*",       # native RS-232
    "/dev/ttyACM*",     # USB CDC-ACM devices
]
GPIB_GLOBS = [
    "/dev/gpib*",       # linux-gpib driver
    "/dev/usbtmc*",     # USB Test & Measurement Class
]

# USB vendor IDs of known cryogenic / lab instrument manufacturers.
# Used to distinguish an instrument from a random USB-serial dongle.
INSTRUMENT_VENDORS = {
    "0403": "FTDI (used by Lakeshore, Cryomagnetics, many instruments)",
    "067b": "Prolific (common serial bridge in lab gear)",
    "10c4": "Silicon Labs CP210x (Bluefors, Oxford adapters)",
    "1234": "Generic / unbranded serial bridge",
    "3923": "National Instruments (GPIB-USB-HS)",
    "0957": "Keysight / Agilent",
    "05e6": "Keithley",
    "1ab1": "Rigol",
}

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_inventory() -> dict:
    try:
        with open(INVENTORY_FILE) as f:
            return json.load(f)
    except:
        return {"devices": {}, "first_seen": now_iso()}

def save_inventory(inv: dict):
    try:
        with open(INVENTORY_FILE, "w") as f:
            json.dump(inv, f, indent=2)
    except:
        pass

def enumerate_bus_devices() -> list:
    """
    Find every serial / USB-serial / GPIB device on the host.
    Runs now, no hardware integration required.
    """
    devices = []
    for pattern in SERIAL_GLOBS + GPIB_GLOBS:
        for path in sorted(glob.glob(pattern)):
            entry = {"path": path, "type": "gpib" if "gpib" in path or "usbtmc" in path
                                          else "serial"}
            try:
                st = os.stat(path)
                entry["mode"]        = oct(st.st_mode & 0o777)
                entry["world_write"] = bool(st.st_mode & stat.S_IWOTH)
                entry["uid"]         = st.st_uid
                entry["gid"]         = st.st_gid
            except Exception:
                pass
            devices.append(entry)
    return devices

def get_usb_serial_identity(dev_path: str) -> dict:
    """
    Resolve a /dev/ttyUSB* device back to its USB vendor and product ID
    by walking sysfs. Identifies whether it's actually lab instrumentation.
    """
    info = {}
    name = os.path.basename(dev_path)
    sys_path = f"/sys/class/tty/{name}/device"
    try:
        real = os.path.realpath(sys_path)
        # Walk up until we find idVendor
        cur = real
        for _ in range(6):
            vid_file = os.path.join(cur, "idVendor")
            pid_file = os.path.join(cur, "idProduct")
            if os.path.exists(vid_file):
                with open(vid_file) as f:
                    vid = f.read().strip().lower()
                pid = ""
                if os.path.exists(pid_file):
                    with open(pid_file) as f:
                        pid = f.read().strip().lower()
                info["vendor_id"]  = vid
                info["product_id"] = pid
                info["vendor"]     = INSTRUMENT_VENDORS.get(vid, "unknown")
                info["is_known_instrument_vendor"] = vid in INSTRUMENT_VENDORS
                for field in ("manufacturer", "product", "serial"):
                    fp = os.path.join(cur, field)
                    if os.path.exists(fp):
                        try:
                            with open(fp) as f:
                                info[field] = f.read().strip()
                        except:
                            pass
                break
            cur = os.path.dirname(cur)
    except Exception:
        pass
    return info

def find_device_holders(dev_path: str) -> list:
    """
    Which processes currently hold this device open?
    Walks /proc/*/fd rather than requiring lsof.
    """
    holders = []
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            fd_dir = f"/proc/{pid_dir}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        target = os.readlink(os.path.join(fd_dir, fd))
                        if target == dev_path:
                            cmd = ""
                            try:
                                with open(f"/proc/{pid_dir}/cmdline", "rb") as f:
                                    cmd = (f.read().replace(b"\x00", b" ")
                                             .decode("utf-8", errors="replace").strip())
                            except:
                                pass
                            holders.append({"pid": int(pid_dir), "cmd": cmd[:160]})
                            break
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue
    except Exception:
        pass
    return holders

def check_socat_shims() -> list:
    """
    socat and similar tools are the standard way to build a serial MITM:
    create a pty pair, sit in the middle, pass traffic through while
    rewriting it. Their presence with a tty argument is a strong signal.
    """
    found = []
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
            low = cmd.lower()
            if not cmd:
                continue
            for tool in ("socat", "ser2net", "remserial", "ttybus", "interceptty"):
                if tool in low and ("tty" in low or "pty" in low or "gpib" in low):
                    found.append({"pid": int(pid_dir), "tool": tool, "cmd": cmd[:200]})
                    break
    except Exception:
        pass
    return found

def analyse(devices: list, inventory: dict) -> tuple:
    """Produce alerts from the bus scan."""
    alerts = []
    known  = inventory.get("devices", {})

    for dev in devices:
        path = dev["path"]

        # ── 1. World-writable instrument device ──
        if dev.get("world_write"):
            alerts.append({
                "event":    "INSTRUMENT_BUS_WORLD_WRITABLE",
                "severity": "CRITICAL",
                "device":   path,
                "mode":     dev.get("mode"),
                "confidence": 0.90,
                "note": ("Instrument bus device is world-writable. Any local "
                         "process can inject commands to the cryogenic "
                         "controller or fabricate sensor responses"),
            })

        # ── 2. Multiple processes holding the same device ──
        holders = find_device_holders(path)
        dev["holders"] = holders
        if len(holders) > MULTI_HOLDER_LIMIT:
            alerts.append({
                "event":    "INSTRUMENT_BUS_MULTI_HOLDER",
                "severity": "CRITICAL",
                "device":   path,
                "holder_count": len(holders),
                "holders":  holders,
                "confidence": 0.80,
                "note": ("More than one process holds this instrument device "
                         "open. Legitimate control daemons hold exclusive "
                         "access — a second holder is the signature of a "
                         "man-in-the-middle shim on the bus"),
            })

        # ── 3. New device appearing since baseline ──
        if path not in known:
            identity = get_usb_serial_identity(path) if "ttyUSB" in path else {}
            dev["identity"] = identity
            sev = "WARN" if identity.get("is_known_instrument_vendor") else "INFO"
            alerts.append({
                "event":    "INSTRUMENT_BUS_NEW_DEVICE",
                "severity": sev,
                "device":   path,
                "identity": identity,
                "confidence": 0.55,
                "note": ("Instrument bus device not present at baseline. "
                         "Verify this is authorised hardware, not an "
                         "attacker-inserted adapter or emulated device"),
            })
        else:
            dev["identity"] = known[path].get("identity", {})

    # ── 4. Serial MITM tooling running ──
    for shim in check_socat_shims():
        alerts.append({
            "event":    "SERIAL_MITM_TOOL_RUNNING",
            "severity": "CRITICAL",
            "pid":      shim["pid"],
            "tool":     shim["tool"],
            "cmd":      shim["cmd"],
            "confidence": 0.85,
            "note": (f"{shim['tool']} is running with a tty/pty argument. This "
                     "is the standard method for building a transparent serial "
                     "man-in-the-middle between an instrument and its daemon"),
        })

    # ── 5. Device disappeared ──
    current_paths = {d["path"] for d in devices}
    for path in known:
        if path not in current_paths:
            alerts.append({
                "event":    "INSTRUMENT_BUS_DEVICE_LOST",
                "severity": "WARN",
                "device":   path,
                "confidence": 0.60,
                "note": ("Instrument device present at baseline is now gone. "
                         "Controller disconnected, or the device node was "
                         "replaced to redirect traffic"),
            })

    # Update inventory
    inventory["devices"] = {d["path"]: {"identity": d.get("identity", {}),
                                         "type":     d.get("type"),
                                         "last_seen": now_iso()}
                             for d in devices}
    return alerts, inventory

def main():
    log = open(f"module55_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "55_cryo_bus_integrity",
        "status": "PARTIAL — bus enumeration functional, sensor cross-validation AWAITING_HARDWARE_INTEGRATION",
        "functional_now": [
            "Serial / USB-serial / GPIB device enumeration",
            "Process-holder detection via /proc/*/fd",
            "Multi-holder MITM signal",
            "Serial MITM tooling detection (socat, ser2net, interceptty)",
            "Device permission audit",
            "Device inventory baseline and drift",
        ],
        "awaiting_hardware": [
            "Out-of-band temperature cross-validation against an independent sensor",
            "Challenge-response probing of controller (detects replay shims)",
            "Setpoint write/read verification",
            "Direct Lakeshore 370/372, Oxford MercuryiTC, Bluefors LD, Pfeiffer MaxiGauge protocol validation",
        ],
        "integration_required": [
            "pyserial or python-vxi11 for direct instrument communication",
            "Read access to /dev/ttyUSB*, /dev/gpib*, or Modbus/TCP endpoint",
            "An independent secondary temperature sensor for cross-validation",
        ],
    })

    inventory = load_inventory()
    alerts    = 0

    while True:
        devices = enumerate_bus_devices()

        emit({"event": "BUS_SCAN",
              "device_count": len(devices),
              "devices": [{"path": d["path"], "type": d["type"],
                           "mode": d.get("mode"),
                           "holders": len(d.get("holders", []))}
                          for d in devices]})

        if not devices:
            emit({"event": "NO_INSTRUMENT_DEVICES",
                  "note": ("No serial or GPIB devices present on this host. "
                           "Either this is not a cryogenic control server, or "
                           "instruments communicate over Modbus/TCP — which "
                           "requires the hardware integration listed above.")})

        new_alerts, inventory = analyse(devices, inventory)
        for a in new_alerts:
            alerts += 1
            emit(a)

        save_inventory(inventory)
        break  # patched: run once and exit instead of infinite monitoring loop
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
