#!/usr/bin/env python3
"""
Watchdog — Module 31: PXE/iSCSI Boot Injection Prevention (B200)
Attack: Attacker intercepts PXE DHCP response, redirects server to malicious
        iSCSI target with compromised OS image that runs before Watchdog loads.
Prevention:
  - Reads /proc/cmdline for netboot/iscsi/pxe flags (runtime detection)
  - Monitors ARP table for DHCP server IP changes (DHCP spoofing detection)
  - Cross-references with module25 (boot_hash) — complementary, not duplicate:
    module25 = file hash tamper | module31 = network boot vector + DHCP spoof
  - On anomaly: log alert + optional firmware reboot

Note: This runs AFTER boot so it detects if the CURRENT boot was a PXE attack,
and also monitors continuously for DHCP spoofing that could affect next reboot.
"""
import subprocess, time, datetime, json, os, re
from collections import deque

POLL_INTERVAL    = 30     # seconds between ARP/DHCP checks
FIRMWARE_REBOOT  = False  # Set True to auto-reboot to UEFI on detection
DHCP_CHANGE_LIMIT = 3     # DHCP server changes before flagging spoof

# Keywords in /proc/cmdline that indicate network/PXE boot
NETBOOT_KEYWORDS = [
    "ip=dhcp", "ip=pxe", "netboot", "iscsi", "root=/dev/nbd",
    "root=nfs", "BOOTIF=", "pxelinux", "ipxe", "tftp",
    "rd.iscsi", "netroot=iscsi",
]

# Expected local boot device patterns
LOCAL_BOOT_PATTERNS = [
    "root=/dev/nvme", "root=/dev/sda", "root=/dev/sdb",
    "root=UUID=", "root=LABEL=",
]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def read_cmdline() -> str:
    try:
        with open("/proc/cmdline") as f:
            return f.read().strip()
    except:
        return ""

def check_pxe_boot(cmdline: str) -> tuple[bool, list]:
    """Return (is_pxe_boot, matched_keywords)."""
    cmdline_lower = cmdline.lower()
    matched = [kw for kw in NETBOOT_KEYWORDS if kw.lower() in cmdline_lower]
    return len(matched) > 0, matched

def check_local_boot(cmdline: str) -> bool:
    """Return True if cmdline shows normal local boot."""
    return any(p.lower() in cmdline.lower() for p in LOCAL_BOOT_PATTERNS)

def get_dhcp_server() -> str | None:
    """Get current DHCP server IP from lease files or ip route."""
    # Try systemd-networkd lease files
    lease_dirs = [
        "/run/systemd/netif/leases",
        "/var/lib/dhcp",
        "/var/lib/dhcpcd",
    ]
    for d in lease_dirs:
        if os.path.exists(d):
            try:
                for f in os.listdir(d):
                    fpath = os.path.join(d, f)
                    with open(fpath) as lf:
                        content = lf.read()
                    for line in content.splitlines():
                        if "SERVER_ADDRESS=" in line or "server-address=" in line:
                            return line.split("=")[-1].strip()
                        if "DHCPSERVER" in line:
                            return line.split()[-1].strip()
            except:
                pass

    # Fallback: check ARP table for gateway
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True, timeout=3)
        m = re.search(r'via (\d+\.\d+\.\d+\.\d+)', out)
        return m.group(1) if m else None
    except:
        return None

def get_arp_table() -> dict:
    """Return {ip: mac} from ARP table."""
    result = {}
    try:
        out = subprocess.check_output(
            ["arp", "-n"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3:
                ip, mac = parts[0], parts[2]
                if mac != "(incomplete)":
                    result[ip] = mac
    except:
        pass
    return result

def check_iscsi_connections() -> list:
    """Check for active iSCSI connections (unexpected = suspicious)."""
    try:
        out = subprocess.check_output(
            ["iscsiadm", "-m", "session"],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
        return out.strip().splitlines() if out.strip() else []
    except:
        return []

def force_firmware_reboot(emit_fn):
    if not FIRMWARE_REBOOT:
        emit_fn({"event": "FIRMWARE_REBOOT_SKIPPED",
                 "note": "Set FIRMWARE_REBOOT=True to enable"})
        return
    try:
        subprocess.check_output(
            ["systemctl", "reboot", "--firmware-setup"], timeout=10)
    except Exception as e:
        emit_fn({"event": "FIRMWARE_REBOOT_FAILED", "error": str(e)})

def main():
    log = open(f"module31_pxe_guard_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    # ── Boot-time check (runs once at startup) ──
    cmdline     = read_cmdline()
    is_pxe, kws = check_pxe_boot(cmdline)
    is_local    = check_local_boot(cmdline)
    iscsi_sess  = check_iscsi_connections()

    emit({"event": "RUN_START", "module": "31_pxe_guard", "gpu": "B200",
          "cmdline": cmdline, "is_pxe_boot": is_pxe,
          "is_local_boot": is_local, "iscsi_sessions": len(iscsi_sess)})

    if is_pxe:
        emit({"event": "PXE_BOOT_DETECTED",
              "matched_keywords": kws,
              "cmdline": cmdline,
              "severity": "CRITICAL",
              "note": "Current boot originated from network — possible iSCSI injection"})
        force_firmware_reboot(emit)

    if not is_local and not is_pxe:
        emit({"event": "BOOT_SOURCE_UNKNOWN",
              "cmdline": cmdline,
              "severity": "WARNING"})

    if iscsi_sess:
        emit({"event": "ISCSI_SESSIONS_ACTIVE",
              "sessions": iscsi_sess,
              "severity": "WARNING" if not is_pxe else "CRITICAL"})

    # ── Runtime monitoring: DHCP spoofing detection ──
    known_dhcp_server = get_dhcp_server()
    known_arp         = get_arp_table()
    dhcp_changes      = deque(maxlen=DHCP_CHANGE_LIMIT + 1)

    emit({"event": "DHCP_BASELINE",
          "dhcp_server": known_dhcp_server,
          "arp_entries": len(known_arp)})

    while True:
        time.sleep(POLL_INTERVAL)

        # DHCP server change detection
        current_dhcp = get_dhcp_server()
        if current_dhcp and known_dhcp_server and \
           current_dhcp != known_dhcp_server:
            dhcp_changes.append({"from": known_dhcp_server,
                                  "to": current_dhcp, "ts": now_iso()})
            emit({"event": "DHCP_SERVER_CHANGED",
                  "from": known_dhcp_server,
                  "to": current_dhcp,
                  "severity": "HIGH"})

            if len(dhcp_changes) >= DHCP_CHANGE_LIMIT:
                emit({"event": "DHCP_SPOOF_DETECTED",
                      "changes": list(dhcp_changes),
                      "severity": "CRITICAL",
                      "note": "Rapid DHCP server rotation = active spoofing"})
                force_firmware_reboot(emit)

            known_dhcp_server = current_dhcp

        # ARP table change detection (MAC spoofing for DHCP server)
        current_arp = get_arp_table()
        for ip, mac in current_arp.items():
            if ip in known_arp and known_arp[ip] != mac:
                emit({"event": "ARP_SPOOF_DETECTED",
                      "ip": ip,
                      "old_mac": known_arp[ip],
                      "new_mac": mac,
                      "severity": "HIGH" if ip == known_dhcp_server else "MEDIUM"})
        known_arp = current_arp

if __name__ == "__main__":
    main()
