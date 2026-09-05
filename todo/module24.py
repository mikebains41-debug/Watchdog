#!/usr/bin/env python3
import sys
sys.exit("UNGATED: this module performs privileged destructive actions with no safety gate. See SECURITY_REVIEW_2026-09-04.md H1. Port module21 gating before running.")

"""
Watchdog — ACPI Power Guard (B200)
Attack: Malformed ACPI _PSR / SMI requests cause rapid PCIe slot power cycling,
        physically resetting the GPU without a software crash.

Prevention:
  - Monitors dmesg for ACPI _PSR and SMI errors
  - Counts occurrences in a 60s sliding window
  - On >3 events: attempts to disable the offending ACPI power source via sysfs
  - Also tries IPMI raw command to lock PSU output (if ipmitool available)
  - Sends alert and logs for manual BIOS intervention if software lock fails

Note: Document suggested /sys/class/power_supply/.../run which doesn't exist.
Real path is /sys/class/power_supply/*/online.
IPMI is the correct channel for PSU-level control on server hardware.
"""
import subprocess, time, datetime, json, os, re
from collections import deque

ACPI_WINDOW     = 60    # seconds for counting ACPI errors
ACPI_THRESHOLD  = 3     # events before action
POLL_INTERVAL   = 2     # seconds between dmesg checks
LOCK_COOLDOWN   = 120   # seconds before re-attempting lock

ACPI_PATTERNS = [
    r'ACPI.*_PSR',
    r'ACPI.*SMI',
    r'ACPI.*power.*error',
    r'SMI.*handler',
    r'ACPI.*firmware.*bug',
    r'ACPI.*malformed',
    r'ACPI.*invalid.*opcode',
]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def get_dmesg_acpi_events() -> list:
    """Return list of ACPI/SMI error lines from dmesg."""
    try:
        out = subprocess.check_output(
            ["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        matches = []
        for line in out.splitlines():
            for pattern in ACPI_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    matches.append(line.strip())
                    break
        return matches
    except:
        return []

def get_power_supplies() -> list:
    """Return list of ACPI power supply sysfs paths."""
    try:
        base = "/sys/class/power_supply"
        return [os.path.join(base, d)
                for d in os.listdir(base)
                if "ACPI" in d.upper() or "AC" in d.upper()]
    except:
        return []

def disable_acpi_power_source(path: str) -> bool:
    """Write 0 to online to disable ACPI power source."""
    try:
        online_path = os.path.join(path, "online")
        if os.path.exists(online_path):
            with open(online_path, "w") as f:
                f.write("0")
            return True
        return False
    except:
        return False

def ipmi_lock_psu() -> bool:
    """
    Use IPMI raw command to request chassis power control.
    0x00 0x02 = chassis control, 0x00 = power down.
    Only fires if ipmitool is available (server/BMC hardware).
    This is a last-resort hard lock.
    """
    try:
        subprocess.check_output(
            ["ipmitool", "mc", "info"],  # DISABLED 2026-09-04: was chassis POWER DOWN (0x00 0x02 0x00). See SECURITY_REVIEW C1.
            timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def ipmi_available() -> bool:
    try:
        subprocess.check_output(
            ["ipmitool", "mc", "info"],
            timeout=3, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def main():
    log = open(f"watchdog_acpi_power_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    has_ipmi = ipmi_available()
    emit({"event": "RUN_START", "module": "acpi_power_guard", "gpu": "B200",
          "acpi_threshold": ACPI_THRESHOLD, "window_s": ACPI_WINDOW,
          "ipmi_available": has_ipmi})

    # Sliding window of (event_line, timestamp) tuples
    event_window: deque = deque()
    seen_lines   = set()    # deduplicate dmesg (it accumulates)
    last_lock    = 0.0

    while True:
        now    = time.time()
        events = get_dmesg_acpi_events()

        for line in events:
            if line not in seen_lines:
                seen_lines.add(line)
                event_window.append((line, now))
                emit({"event": "ACPI_ERROR_DETECTED", "log": line})

        # Purge events outside window
        while event_window and (now - event_window[0][1]) > ACPI_WINDOW:
            event_window.popleft()

        if len(event_window) >= ACPI_THRESHOLD and \
           now - last_lock > LOCK_COOLDOWN:

            recent = [e for e, _ in event_window]
            emit({"event": "ACPI_ATTACK_THRESHOLD_HIT",
                  "count": len(event_window),
                  "window_s": ACPI_WINDOW,
                  "events": recent[-5:]})

            # Attempt 1: sysfs power supply disable
            supplies = get_power_supplies()
            locked = False
            for path in supplies:
                if disable_acpi_power_source(path):
                    emit({"event": "ACPI_POWER_SOURCE_DISABLED",
                          "path": path,
                          "action": "online=0"})
                    locked = True

            # Attempt 2: IPMI PSU lock (server hardware)
            if not locked and has_ipmi:
                if ipmi_lock_psu():
                    emit({"event": "IPMI_PSU_LOCK",
                          "action": "chassis_power_down",
                          "note": "HARD LOCK — manual recovery required"})
                    locked = True

            if not locked:
                emit({"event": "ACPI_LOCK_FAILED",
                      "note": "No sysfs path or IPMI available — manual BIOS intervention required"})

            last_lock = now

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
