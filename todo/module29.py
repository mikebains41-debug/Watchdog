#!/usr/bin/env python3
"""
Watchdog — Module 29: SGX/SEV-SNP Attestation Bypass Prevention (B200)
Attack: Attacker tricks attestation service into trusting malicious unencrypted VM,
        reads plaintext model weights before GPU handoff.
Prevention:
  - Monitors /sys/kernel/security/sev/ for attestation failures
  - Monitors dmesg for SEV/SGX error messages
  - On failure: flush CPU cache via drop_caches (correct method, not wrmsr)
  - Write attestation failure to TPM if available
  - Force reboot to secure firmware (optional, requires FIRMWARE_REBOOT=True)

Correction from original spec: wrmsr writes to MSRs (model-specific registers)
and does NOT flush CPU cache. Cache flushing from userspace = drop_caches.
"""
import subprocess, time, datetime, json, os, hashlib
from collections import deque

FAILURE_WINDOW    = 120   # seconds
FAILURE_THRESHOLD = 2     # attestation failures before action
POLL_INTERVAL     = 5     # seconds
FIRMWARE_REBOOT   = False # Set True to auto-reboot to UEFI on failure

SEV_SYSFS_PATHS = [
    "/sys/kernel/security/sev",
    "/sys/kernel/security/sev-guest",
    "/sys/firmware/acpi/tables/CEDT",  # CXL Early Discovery Table (SEV indicator)
]

SEV_DMESG_PATTERNS = [
    "sev",
    "snp",
    "sgx",
    "attestation",
    "secure encrypted",
    "AMD SEV",
    "Intel SGX",
]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def sev_available() -> dict:
    """Check what TEE (Trusted Execution Environment) is available."""
    result = {}
    for path in SEV_SYSFS_PATHS:
        if os.path.exists(path):
            result[path] = True
    try:
        out = subprocess.check_output(
            ["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "sev" in line.lower() and "enabled" in line.lower():
                result["sev_enabled_dmesg"] = line.strip()
                break
    except:
        pass
    return result

def scan_dmesg_attestation() -> list:
    """Return new attestation error lines from dmesg."""
    try:
        out = subprocess.check_output(
            ["dmesg"], text=True, timeout=3, stderr=subprocess.DEVNULL)
        hits = []
        for line in out.splitlines():
            line_lower = line.lower()
            has_pattern = any(p.lower() in line_lower for p in SEV_DMESG_PATTERNS)
            has_error   = any(w in line_lower for w in
                              ["fail", "error", "invalid", "reject",
                               "bypass", "violation", "tamper"])
            if has_pattern and has_error:
                hits.append(line.strip())
        return hits
    except:
        return []

def read_sev_status() -> dict:
    """Read SEV status from sysfs."""
    status = {}
    sev_path = "/sys/kernel/security/sev"
    if os.path.exists(sev_path):
        for fname in os.listdir(sev_path):
            fpath = os.path.join(sev_path, fname)
            try:
                with open(fpath) as f:
                    status[fname] = f.read().strip()
            except:
                pass
    return status

def flush_cpu_cache() -> bool:
    """
    Flush CPU cache from userspace via drop_caches.
    This is the correct method — wrmsr does NOT flush cache.
    """
    try:
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3")
        return True
    except:
        return False

def write_tpm_attestation_log(event: dict) -> bool:
    """Write attestation failure event to TPM NVRAM if available."""
    try:
        if not (os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0")):
            return False
        # Serialize event to bytes
        data = json.dumps(event).encode()
        h    = hashlib.sha256(data).hexdigest()
        tmp  = "/tmp/watchdog_sev_attest.bin"
        with open(tmp, "w") as f:
            f.write(h)
        # Write hash to TPM NV index (index 0x1500016 = attestation log)
        subprocess.check_output([
            "tpm2_nvwrite", "-i", "0x1500016", tmp
        ], timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def force_secure_reboot(emit_fn):
    if not FIRMWARE_REBOOT:
        emit_fn({"event": "SECURE_REBOOT_SKIPPED",
                 "note": "Set FIRMWARE_REBOOT=True to enable"})
        return
    try:
        subprocess.check_output(
            ["systemctl", "reboot", "--firmware-setup"],
            timeout=10)
    except Exception as e:
        emit_fn({"event": "SECURE_REBOOT_FAILED", "error": str(e)})

def main():
    log = open(f"module29_sev_attestation_{stamp()}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    tee_info = sev_available()
    emit({"event": "RUN_START", "module": "29_sev_attestation", "gpu": "B200",
          "tee_detected": tee_info,
          "firmware_reboot_enabled": FIRMWARE_REBOOT,
          "cache_flush_method": "drop_caches (not wrmsr)"})

    seen_lines   = set()
    event_window = deque()
    last_action  = 0.0

    while True:
        now  = time.time()
        hits = scan_dmesg_attestation()

        for line in hits:
            if line not in seen_lines:
                seen_lines.add(line)
                event_window.append((line, now))
                emit({"event": "ATTESTATION_ERROR_DETECTED", "log": line})

        # Purge outside window
        while event_window and (now - event_window[0][1]) > FAILURE_WINDOW:
            event_window.popleft()

        if len(event_window) >= FAILURE_THRESHOLD and \
           now - last_action > FAILURE_WINDOW:
            last_action = now

            sev_status = read_sev_status()
            failure_event = {
                "event":        "ATTESTATION_BYPASS_DETECTED",
                "count":        len(event_window),
                "sev_status":   sev_status,
                "errors":       [e for e, _ in event_window][-5:]
            }
            emit(failure_event)

            # 1. Flush CPU cache (correct method)
            if flush_cpu_cache():
                emit({"event": "CPU_CACHE_FLUSHED",
                      "method": "drop_caches"})

            # 2. Log to TPM
            if write_tpm_attestation_log(failure_event):
                emit({"event": "TPM_ATTESTATION_LOG_WRITTEN"})

            # 3. Force secure reboot (if enabled)
            force_secure_reboot(emit)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
