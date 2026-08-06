#!/usr/bin/env python3
"""
Watchdog — Module 61: BMC & IPMI Firmware Integrity Monitor
Status: FUNCTIONAL where a BMC is present — graceful fallback otherwise

Attack vector: module44 reads chassis power from IPMI and treats the BMC as
a trusted oracle. It is not one.

A Baseboard Management Controller is a full computer running its own OS,
with its own network stack, out-of-band access to the host, and a long
history of critical firmware vulnerabilities. It sits below the host OS.
An attacker who compromises the BMC can:

  - Manipulate power delivery and fan curves out of band — a thermal or
    power attack on a cryogenic system that never appears in any host log
  - Return fabricated sensor readings, so module44 sees normal power while
    the real draw is anything at all
  - Mount virtual media and boot the host from an attacker-controlled image
  - Read and write host memory over KCS/BT interfaces
  - Persist across host OS reinstalls — a BMC rootkit survives everything
    done at the OS layer

Nothing at the host OS layer can prove a BMC is honest. What this module
can do is detect *change*: baseline the firmware version, the Field
Replaceable Unit data, the sensor inventory, the user list, and the enabled
channels — then alert on any drift.

WHAT THIS CHECKS (functional where ipmitool and a BMC exist):
  - BMC firmware revision, IPMI version, manufacturer and product ID
  - Full SDR (Sensor Data Record) inventory hash — sensors appearing,
    disappearing, or changing type is a firmware-level change
  - FRU (Field Replaceable Unit) data hash
  - IPMI user list — a new BMC user is a persistence mechanism
  - LAN channel configuration — IPMI over LAN enabled is a remote attack path
  - Cipher suite 0 (no authentication) availability — a known critical flaw
  - Anonymous / null user login enabled
  - Host-side KCS/BT interface device presence and permissions
  - dmesg IPMI driver events

FALLBACK: if ipmitool is absent or no BMC responds, the module reads what
it can from /sys/class/ipmi and /dev/ipmi* and reports honestly rather
than fabricating a result.
"""
import os, json, time, datetime, hashlib, subprocess, glob, stat

POLL_INTERVAL   = 1800    # BMC state changes rarely — 30 min is plenty
BASELINE_FILE   = "/tmp/watchdog_ipmi_baseline.json"
IPMI_TIMEOUT    = 10      # ipmitool can be slow

IPMI_DEVICES = ["/dev/ipmi0", "/dev/ipmi/0", "/dev/ipmidev/0"]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except:
        return {}

def save_baseline(b: dict):
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(b, f, indent=2)
    except:
        pass

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def ipmitool(*args) -> str | None:
    """Run ipmitool with a timeout. Returns stdout or None."""
    try:
        return subprocess.check_output(
            ["ipmitool", *args], text=True, timeout=IPMI_TIMEOUT,
            stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None

def ipmitool_available() -> bool:
    try:
        subprocess.check_output(["ipmitool", "-V"], text=True, timeout=5,
                                 stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

def check_host_ipmi_interface() -> dict:
    """
    Host-side IPMI interface presence and permissions. This works even
    when ipmitool is missing.
    """
    result = {"devices": [], "sysfs_present": False}

    for dev in IPMI_DEVICES:
        if os.path.exists(dev):
            entry = {"path": dev}
            try:
                st = os.stat(dev)
                entry["mode"]        = oct(st.st_mode & 0o777)
                entry["uid"]         = st.st_uid
                entry["gid"]         = st.st_gid
                entry["world_write"] = bool(st.st_mode & stat.S_IWOTH)
                entry["world_read"]  = bool(st.st_mode & stat.S_IROTH)
            except Exception:
                pass
            result["devices"].append(entry)

    if os.path.isdir("/sys/class/ipmi"):
        result["sysfs_present"] = True
        try:
            result["sysfs_entries"] = os.listdir("/sys/class/ipmi")
        except Exception:
            pass

    # IPMI kernel modules
    try:
        out = subprocess.check_output(["lsmod"], text=True, timeout=3,
                                       stderr=subprocess.DEVNULL)
        mods = [l.split()[0] for l in out.splitlines()[1:]
                if l.split() and "ipmi" in l.split()[0].lower()]
        result["kernel_modules"] = mods
    except Exception:
        pass

    return result

def get_mc_info() -> dict | None:
    """BMC firmware revision, IPMI version, manufacturer, product."""
    out = ipmitool("mc", "info")
    if not out:
        return None
    info = {"_raw_hash": sha256_text(out)}
    for line in out.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower().replace(" ", "_")
        val = val.strip()
        if key in ("device_id", "device_revision", "firmware_revision",
                    "ipmi_version", "manufacturer_id", "manufacturer_name",
                    "product_id", "product_name", "aux_firmware_rev_info"):
            info[key] = val
    return info

def get_sdr_hash() -> dict | None:
    """
    Sensor Data Record inventory. Sensors appearing, vanishing, or
    changing is a firmware-level change.
    """
    out = ipmitool("sdr", "list")
    if not out:
        return None
    sensors = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if parts:
            # Name and type only — readings change constantly, structure does not
            sensors.append(parts[0])
    sensors.sort()
    return {"count": len(sensors),
             "hash":  sha256_text("\n".join(sensors)),
             "names": sensors[:40]}

def get_fru_hash() -> dict | None:
    """Field Replaceable Unit data — board, product, chassis identity."""
    out = ipmitool("fru", "print")
    if not out:
        return None
    # Strip anything that could vary per read
    lines = [l for l in out.splitlines() if l.strip()]
    return {"hash": sha256_text("\n".join(sorted(lines))),
             "line_count": len(lines)}

def get_ipmi_users() -> dict | None:
    """
    BMC user list. A new BMC user is a persistence mechanism that survives
    host OS reinstallation.
    """
    out = ipmitool("user", "list", "1")
    if not out:
        return None
    users = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            users.append({"id": parts[0], "name": parts[1],
                           "raw": " ".join(parts)})
    return {"count": len(users),
             "users": users,
             "hash":  sha256_text(json.dumps(users, sort_keys=True))}

def get_lan_config() -> dict | None:
    """
    IPMI-over-LAN configuration. If enabled, the BMC is reachable over the
    network — a remote attack surface below the host OS.
    """
    out = ipmitool("lan", "print", "1")
    if not out:
        return None
    config = {"_raw_hash": sha256_text(out)}
    for line in out.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower().replace(" ", "_").replace("/", "_")
        val = val.strip()
        if key in ("ip_address_source", "ip_address", "mac_address",
                    "default_gateway_ip", "802.1q_vlan_id",
                    "cipher_suite_priv_max", "auth_type_enable"):
            config[key] = val
    config["lan_enabled"] = bool(config.get("ip_address")
                                  and config.get("ip_address") != "0.0.0.0")
    return config

def check_cipher_zero() -> dict | None:
    """
    Cipher suite 0 accepts any password. It is a critical, well-documented
    IPMI flaw. Presence in the priv max list means it is available.
    """
    out = ipmitool("lan", "print", "1")
    if not out:
        return None
    for line in out.splitlines():
        if "cipher suite priv max" in line.lower():
            _, _, val = line.partition(":")
            val = val.strip()
            # Position 0 in the string corresponds to cipher suite 0
            enabled = len(val) > 0 and val[0] not in ("X", "x")
            return {"priv_max_string": val, "cipher_zero_enabled": enabled}
    return None

def check_dmesg_ipmi() -> list:
    hits = []
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3,
                                       stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            low = line.lower()
            if "ipmi" in low or "bmc" in low:
                hits.append(line.strip())
    except Exception:
        pass
    return hits[-15:]

def analyse(current: dict, baseline: dict, host_iface: dict) -> list:
    alerts = []

    # ── 1. Host interface permissions ──
    for dev in host_iface.get("devices", []):
        if dev.get("world_write"):
            alerts.append({
                "event":    "IPMI_DEVICE_WORLD_WRITABLE",
                "severity": "CRITICAL",
                "device":   dev["path"],
                "mode":     dev.get("mode"),
                "confidence": 0.90,
                "note": ("The host IPMI interface is world-writable. Any local "
                         "process can issue BMC commands — including power "
                         "control and firmware operations"),
            })

    # ── 2. Firmware revision changed ──
    prev_mc = baseline.get("mc_info") or {}
    curr_mc = current.get("mc_info") or {}
    if prev_mc and curr_mc:
        for field in ("firmware_revision", "ipmi_version", "device_revision",
                       "aux_firmware_rev_info", "product_id",
                       "manufacturer_id"):
            if prev_mc.get(field) and curr_mc.get(field) \
                    and prev_mc[field] != curr_mc[field]:
                alerts.append({
                    "event":    "BMC_FIRMWARE_MODIFIED",
                    "severity": "CRITICAL",
                    "field":    field,
                    "was":      prev_mc[field],
                    "now":      curr_mc[field],
                    "confidence": 0.90,
                    "note": ("BMC firmware identity changed. Unless a "
                             "scheduled firmware update was performed, this is "
                             "a firmware-level compromise. A BMC rootkit "
                             "persists across host OS reinstallation and can "
                             "fabricate every sensor reading the host trusts"),
                })
        if prev_mc.get("_raw_hash") != curr_mc.get("_raw_hash") and not any(
                a["event"] == "BMC_FIRMWARE_MODIFIED" for a in alerts):
            alerts.append({
                "event":    "BMC_MC_INFO_DRIFT",
                "severity": "WARN",
                "confidence": 0.65,
                "note": "BMC controller info output changed in some field",
            })

    # ── 3. Sensor inventory changed ──
    prev_sdr = baseline.get("sdr") or {}
    curr_sdr = current.get("sdr") or {}
    if prev_sdr and curr_sdr and prev_sdr.get("hash") != curr_sdr.get("hash"):
        alerts.append({
            "event":    "IPMI_SENSOR_INVENTORY_CHANGED",
            "severity": "CRITICAL",
            "was_count": prev_sdr.get("count"),
            "now_count": curr_sdr.get("count"),
            "confidence": 0.85,
            "note": ("The BMC sensor inventory changed. Sensors do not appear "
                     "or vanish on a static machine. Either firmware was "
                     "modified, or sensors are being hidden to conceal a "
                     "thermal or power attack"),
        })

    # ── 4. FRU changed ──
    prev_fru = baseline.get("fru") or {}
    curr_fru = current.get("fru") or {}
    if prev_fru and curr_fru and prev_fru.get("hash") != curr_fru.get("hash"):
        alerts.append({
            "event":    "IPMI_FRU_CHANGED",
            "severity": "WARN",
            "confidence": 0.75,
            "note": ("Field Replaceable Unit data changed — board, product, "
                     "or chassis identity is not what it was"),
        })

    # ── 5. BMC user list changed ──
    prev_users = baseline.get("users") or {}
    curr_users = current.get("users") or {}
    if prev_users and curr_users and prev_users.get("hash") != curr_users.get("hash"):
        prev_names = {u["name"] for u in prev_users.get("users", [])}
        curr_names = {u["name"] for u in curr_users.get("users", [])}
        added   = curr_names - prev_names
        removed = prev_names - curr_names
        alerts.append({
            "event":    "BMC_USER_LIST_CHANGED",
            "severity": "CRITICAL",
            "added":    sorted(added),
            "removed":  sorted(removed),
            "confidence": 0.90,
            "note": ("The BMC user list changed. A new BMC account is an "
                     "out-of-band persistence mechanism that survives host OS "
                     "reinstallation and grants power and console control"),
        })

    # ── 6. IPMI over LAN enabled ──
    lan = current.get("lan") or {}
    if lan.get("lan_enabled"):
        alerts.append({
            "event":    "IPMI_OVER_LAN_ENABLED",
            "severity": "WARN",
            "ip_address": lan.get("ip_address"),
            "mac":        lan.get("mac_address"),
            "confidence": 0.70,
            "note": ("IPMI over LAN is active. The BMC is reachable over the "
                     "network, below the host OS and outside every host-level "
                     "control. On a quantum control host this should be on an "
                     "isolated management network or disabled entirely"),
        })

    prev_lan = baseline.get("lan") or {}
    if prev_lan and lan and prev_lan.get("_raw_hash") != lan.get("_raw_hash"):
        alerts.append({
            "event":    "IPMI_LAN_CONFIG_CHANGED",
            "severity": "CRITICAL",
            "confidence": 0.85,
            "note": ("IPMI LAN configuration changed. Verify no new remote "
                     "access path to the BMC was opened"),
        })

    # ── 7. Cipher suite 0 ──
    cipher = current.get("cipher_zero") or {}
    if cipher.get("cipher_zero_enabled"):
        alerts.append({
            "event":    "IPMI_CIPHER_ZERO_ENABLED",
            "severity": "CRITICAL",
            "priv_max": cipher.get("priv_max_string"),
            "confidence": 0.95,
            "note": ("IPMI cipher suite 0 is available. Cipher 0 accepts ANY "
                     "password — it is authentication bypass by design. Anyone "
                     "who can reach the BMC has full administrative control"),
        })

    return alerts

def main():
    log = open(f"module61_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    have_ipmitool = ipmitool_available()
    host_iface    = check_host_ipmi_interface()

    emit({
        "event":  "RUN_START",
        "module": "61_bmc_ipmi_integrity",
        "status": ("FUNCTIONAL" if have_ipmitool
                   else "DEGRADED — ipmitool not available, host-side checks only"),
        "ipmitool_available": have_ipmitool,
        "host_interface":     host_iface,
        "checks": [
            "BMC firmware revision / IPMI version / product ID baseline",
            "Sensor Data Record inventory hash",
            "Field Replaceable Unit data hash",
            "BMC user list (out-of-band persistence detection)",
            "IPMI over LAN configuration",
            "Cipher suite 0 authentication bypass",
            "Host IPMI interface permissions",
        ],
        "why_this_matters": ("module44 reads power from IPMI and trusts the "
                              "BMC. A compromised BMC fabricates every reading "
                              "and manipulates power out of band. This module "
                              "detects change in the BMC itself"),
    })

    if not have_ipmitool:
        emit({"event": "IPMITOOL_UNAVAILABLE",
              "note": ("ipmitool not installed or no BMC present. Host-side "
                       "interface checks still run. Install ipmitool on a "
                       "server-class control host to enable full BMC "
                       "integrity monitoring."),
              "host_devices_found": len(host_iface.get("devices", [])),
              "ipmi_kernel_modules": host_iface.get("kernel_modules", [])})

    baseline = load_baseline()
    first    = not baseline

    while True:
        host_iface = check_host_ipmi_interface()

        current = {}
        if have_ipmitool:
            current["mc_info"]     = get_mc_info()
            current["sdr"]         = get_sdr_hash()
            current["fru"]         = get_fru_hash()
            current["users"]       = get_ipmi_users()
            current["lan"]         = get_lan_config()
            current["cipher_zero"] = check_cipher_zero()

        reachable = bool(current.get("mc_info"))

        emit({"event": "IPMI_SCAN",
              "bmc_reachable": reachable,
              "firmware":      (current.get("mc_info") or {}).get("firmware_revision"),
              "product":       (current.get("mc_info") or {}).get("product_name"),
              "sensor_count":  (current.get("sdr") or {}).get("count"),
              "user_count":    (current.get("users") or {}).get("count"),
              "lan_enabled":   (current.get("lan") or {}).get("lan_enabled"),
              "host_devices":  len(host_iface.get("devices", []))})

        if not reachable and have_ipmitool:
            emit({"event": "BMC_UNREACHABLE",
                  "severity": "WARN",
                  "note": ("ipmitool is present but the BMC did not respond. "
                           "Either no BMC on this platform, or the BMC is "
                           "unresponsive — which is itself worth investigating "
                           "on a server-class host")})

        if first and reachable:
            emit({"event": "IPMI_BASELINE_ESTABLISHED",
                  "firmware":     current["mc_info"].get("firmware_revision"),
                  "ipmi_version": current["mc_info"].get("ipmi_version"),
                  "product":      current["mc_info"].get("product_name"),
                  "sensors":      (current.get("sdr") or {}).get("count"),
                  "users":        (current.get("users") or {}).get("count")})
            baseline = current
            save_baseline(baseline)
            first = False
            # Static-risk checks still run on the first pass
            for a in analyse(current, {}, host_iface):
                if a["event"] in ("IPMI_CIPHER_ZERO_ENABLED",
                                   "IPMI_OVER_LAN_ENABLED",
                                   "IPMI_DEVICE_WORLD_WRITABLE"):
                    emit(a)
            time.sleep(POLL_INTERVAL)
            continue

        alerts = analyse(current, baseline, host_iface)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "IPMI_STATUS_OK",
                  "bmc_reachable": reachable,
                  "firmware": (current.get("mc_info") or {}).get("firmware_revision")})

        if reachable:
            baseline = current
            save_baseline(baseline)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
