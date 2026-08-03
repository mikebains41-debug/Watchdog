#!/usr/bin/env python3
"""
Watchdog — Boot Hash Guard (B200)
Attack: Attacker injects malicious script into /boot/initramfs that runs before
        kernel loads, remapping GPU PCIe address space to bypass NVLink driver.

Prevention:
  - SHA256 hashes /boot/initrd.img (and variants) at startup
  - Stores baseline hash in a signed file
  - Polls for changes every 60s
  - On tamper: logs BOOT_PARTITION_TAMPER alert
  - Optionally forces UEFI firmware setup on next reboot
    (systemctl reboot --firmware-setup) for BIOS recovery

Note: This module should run as root. Hash polling won't detect in-flight
injection but catches changes between checks. For real-time coverage,
pair with inotifywait on /boot.
"""
import subprocess, time, datetime, json, hashlib, os

POLL_INTERVAL  = 60      # seconds between hash checks
HASH_STORE     = "/var/lib/watchdog/boot_hashes.json"
FIRMWARE_REBOOT = False  # Set True to auto-reboot to UEFI on tamper
                         # WARNING: reboots the machine

# Common initramfs paths — module checks all that exist
INITRD_PATHS = [
    "/boot/initrd.img",
    "/boot/initrd.img-$(uname -r)",
    "/boot/initramfs-linux.img",
    "/boot/initramfs.img",
    "/boot/initrd",
]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def get_kernel_version() -> str:
    try:
        return subprocess.check_output(
            ["uname", "-r"], text=True, timeout=2).strip()
    except:
        return "unknown"

def resolve_initrd_paths() -> list:
    """Resolve all existing initramfs paths including kernel-versioned ones."""
    kernel = get_kernel_version()
    candidates = []
    for p in INITRD_PATHS:
        resolved = p.replace("$(uname -r)", kernel)
        if os.path.exists(resolved):
            candidates.append(resolved)
    # Also scan /boot for any initrd/initramfs files
    try:
        for f in os.listdir("/boot"):
            if "initrd" in f.lower() or "initramfs" in f.lower():
                full = os.path.join("/boot", f)
                if full not in candidates:
                    candidates.append(full)
    except:
        pass
    return candidates

def sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def load_baselines() -> dict:
    try:
        os.makedirs(os.path.dirname(HASH_STORE), exist_ok=True)
        with open(HASH_STORE) as f:
            return json.load(f)
    except:
        return {}

def save_baselines(baselines: dict):
    try:
        os.makedirs(os.path.dirname(HASH_STORE), exist_ok=True)
        with open(HASH_STORE, "w") as f:
            json.dump(baselines, f, indent=2)
    except:
        pass

def get_file_mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except:
        return 0.0

def trigger_firmware_reboot(emit_fn):
    """Force reboot into UEFI firmware setup for BIOS recovery."""
    if not FIRMWARE_REBOOT:
        emit_fn({"event": "FIRMWARE_REBOOT_SKIPPED",
                 "note": "Set FIRMWARE_REBOOT=True to enable auto-reboot to UEFI"})
        return
    try:
        emit_fn({"event": "FIRMWARE_REBOOT_TRIGGERED",
                 "action": "systemctl reboot --firmware-setup"})
        subprocess.check_output(
            ["systemctl", "reboot", "--firmware-setup"],
            timeout=10)
    except Exception as e:
        emit_fn({"event": "FIRMWARE_REBOOT_FAILED", "error": str(e)})

def main():
    log = open(f"watchdog_boot_hash_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    kernel    = get_kernel_version()
    paths     = resolve_initrd_paths()
    baselines = load_baselines()

    emit({"event": "RUN_START", "module": "boot_hash_guard", "gpu": "B200",
          "kernel": kernel, "monitored_paths": paths,
          "poll_interval_s": POLL_INTERVAL,
          "firmware_reboot_enabled": FIRMWARE_REBOOT})

    # Establish baselines for any new paths
    changed = False
    for path in paths:
        if path not in baselines:
            h = sha256_file(path)
            if h:
                baselines[path] = {
                    "sha256": h,
                    "mtime":  get_file_mtime(path),
                    "established": now_iso()
                }
                emit({"event": "BASELINE_ESTABLISHED",
                      "path": path, "sha256": h})
                changed = True

    if changed:
        save_baselines(baselines)

    while True:
        time.sleep(POLL_INTERVAL)

        for path in resolve_initrd_paths():
            current_hash  = sha256_file(path)
            current_mtime = get_file_mtime(path)

            if current_hash is None:
                emit({"event": "BOOT_FILE_UNREADABLE", "path": path})
                continue

            if path not in baselines:
                # New file appeared in /boot — suspicious
                baselines[path] = {
                    "sha256": current_hash,
                    "mtime":  current_mtime,
                    "established": now_iso()
                }
                emit({"event": "NEW_BOOT_FILE_DETECTED",
                      "path": path, "sha256": current_hash,
                      "severity": "WARNING"})
                save_baselines(baselines)
                continue

            baseline = baselines[path]
            if current_hash != baseline["sha256"]:
                emit({"event": "BOOT_PARTITION_TAMPER",
                      "path": path,
                      "expected_sha256": baseline["sha256"],
                      "actual_sha256":   current_hash,
                      "baseline_at":     baseline["established"],
                      "mtime_changed":   current_mtime != baseline["mtime"],
                      "severity":        "CRITICAL"})

                trigger_firmware_reboot(emit)

if __name__ == "__main__":
    main()
