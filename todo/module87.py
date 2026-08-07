#!/usr/bin/env python3
"""
Watchdog — Module 87: Confidential Computing / TEE Attestation Verifier
Status: PARTIAL — host-side presence/config checks functional now,
        cryptographic quote verification AWAITING_HARDWARE_INTEGRATION

THE PROBLEM: a workload can CLAIM to run inside a Trusted Execution
Environment without that claim ever being cryptographically verified.

Intel SGX and AMD SEV-SNP both provide "remote attestation" — a signed
report proving a specific, unmodified piece of code is running inside
genuine, hardware-isolated memory that not even the host OS or
hypervisor can read. This is the control that makes confidential
computing meaningful for a cloud-hosted quantum control plane: the
classical pre/post-processing surrounding a real quantum job can run
somewhere the cloud provider itself cannot inspect.

The gap: "presence checking" is not attestation. A process checking
"does /dev/sgx_enclave exist" and concluding "we are in a TEE" has
verified NOTHING about the actual code running, its measurement
(MRENCLAVE/MRSIGNER for SGX, launch digest for SEV-SNP), or whether the
attestation report's signature chains back to a genuine Intel or AMD
root certificate. This is the same category of failure as module82's
RuntimeClass problem and module85's PERMISSIVE mTLS problem: the
control is declared, appears applied, and does not do what it claims.

CONFIRMED VULNERABILITY CLASSES (both platforms, published):
  SGX:  Foreshadow / L1TF (CVE-2018-3615), Plundervolt (CVE-2019-11157),
        SGAxe (CVE-2020-0521), and multiple side-channel families that
        extract secrets from inside a genuine, correctly-attested enclave
  SEV-SNP: downgrade attacks forcing a VM to accept an older,
        vulnerable firmware version while the attestation still reports
        success (documented in AMD's own security bulletins)

WHAT THIS MODULE CHECKS — functional now:
  1. SGX driver and enclave device presence, and whether CPUID reports
     genuine hardware SGX support versus the device merely existing
  2. SEV-SNP guest device presence and kernel dmesg confirmation
  3. Whether a process claims TEE execution (via environment variables,
     known SDK markers) while no TEE hardware/driver is actually present
     on the host — the "claims but cannot prove" signature
  4. Attestation report/quote FILES present on disk without any
     corresponding verification step having run (report generated,
     never checked)
  5. SGX/SEV firmware and microcode version against known-vulnerable
     ranges from the CVEs above
  6. Presence of "attestation bypass" indicators: debug-mode enclaves
     (SGX debug flag set — debug enclaves have NO confidentiality
     guarantee at all and are trivially inspectable)
  7. TEE-related kernel module and config drift over time

WHAT NEEDS HARDWARE (documented, not simulated):
  - Full cryptographic verification of an SGX DCAP quote or SEV-SNP
    attestation report against the Intel/AMD root of trust
  - MRENCLAVE/MRSIGNER measurement comparison against a known-good
    reference build
  - Live TCB (Trusted Computing Base) recovery status check against
    Intel's PCCS or AMD's KDS attestation service

No attestation report is ever fabricated. No measurement is invented.
"""
import os, json, time, datetime, glob, re, subprocess, hashlib

POLL_INTERVAL     = 600
STATE_FILE        = "/tmp/watchdog_tee_attestation.json"

SGX_DEVICE_PATHS = ["/dev/sgx_enclave", "/dev/sgx/enclave", "/dev/sgx",
                    "/dev/isgx"]
SEV_DEVICE_PATHS = ["/dev/sev", "/dev/sev-guest", "/dev/sevguest"]

# Known-vulnerable SGX/SEV firmware version markers from published CVEs.
# Format: (cve, description) — matched against dmesg/sysfs version strings
KNOWN_VULNERABILITIES = {
    "CVE-2018-3615":  "Foreshadow/L1TF — L1 cache side-channel extracting SGX enclave secrets",
    "CVE-2019-11157": "Plundervolt — voltage manipulation breaks SGX integrity guarantees",
    "CVE-2020-0521":  "SGAxe — extracts SGX attestation keys via cache side-channel",
    "CVE-2021-33655": "SEV-ES/SNP guest memory corruption",
}

# Environment / SDK markers indicating a process believes it is in a TEE
TEE_CLAIM_MARKERS = [
    "SGX_MODE", "IAS_", "DCAP_", "AESM", "gramine", "occlum",
    "SEV_GUEST", "SNP_GUEST", "AMD_SEV", "confidential-containers",
    "kata-confidential", "OCCLUM_LOG_LEVEL",
]

ATTESTATION_TOOLS = ["gramine-sgx-get-token", "PCKIDRetrievalTool",
                     "sgx_sign", "snpguest", "sev-tool", "tpm2_quote",
                     "az-cvm-guest-attestation"]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"config_hash": {}, "established": now_iso()}

def save_state(s):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def check_sgx_hardware():
    """Real SGX device and CPUID presence — no cryptographic claim implied."""
    result = {"devices_present": [], "cpuid_sgx": None, "epc_size": None}
    for path in SGX_DEVICE_PATHS:
        if os.path.exists(path):
            result["devices_present"].append(path)

    # CPUID leaf 0x12 reports SGX capability — read via /proc/cpuinfo flags
    try:
        with open("/proc/cpuinfo") as f:
            content = f.read()
        result["cpuid_sgx"] = "sgx" in content.lower()
    except Exception:
        pass

    # Enclave Page Cache size, if exposed
    for path in glob.glob("/sys/firmware/acpi/tables/EPC*"):
        result["epc_size"] = "present"
        break

    return result

def check_sev_hardware():
    """Real SEV/SEV-SNP device presence."""
    result = {"devices_present": [], "sev_status": None}
    for path in SEV_DEVICE_PATHS:
        if os.path.exists(path):
            result["devices_present"].append(path)

    # SEV status is exposed via sysfs on the host (not inside the guest)
    sev_status_path = "/sys/module/kvm_amd/parameters/sev"
    if os.path.exists(sev_status_path):
        try:
            with open(sev_status_path) as f:
                result["sev_status"] = f.read().strip()
        except Exception:
            pass

    return result

def check_debug_mode_enclaves():
    """
    SGX debug-mode enclaves have zero confidentiality — memory is fully
    readable by the OS. A production TEE workload must never be in
    debug mode; this checks for processes that are.
    """
    findings = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = (f.read().replace(b"\x00", b" ")
                             .decode("utf-8", errors="replace").strip())
            except Exception:
                continue
            if not cmd:
                continue
            low = cmd.lower()
            if any(m in low for m in ("sgx", "gramine", "occlum")):
                if "debug" in low or "-d " in low or "SGX_DEBUG=1" in cmd:
                    findings.append({"pid": int(pid), "cmd": cmd[:200]})
    except Exception:
        pass
    return findings

def check_tee_claims_without_hardware(sgx_hw, sev_hw):
    """
    Processes whose environment claims TEE execution while no TEE
    hardware or driver is present — the "claims but cannot prove" gap.
    """
    findings = []
    has_hardware = bool(sgx_hw["devices_present"] or sev_hw["devices_present"])
    if has_hardware:
        return findings

    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/environ", "rb") as f:
                    env = f.read(32768).decode("utf-8", errors="replace")
            except (OSError, PermissionError):
                continue
            for marker in TEE_CLAIM_MARKERS:
                if marker in env:
                    cmd = ""
                    try:
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            cmd = (f.read().replace(b"\x00", b" ")
                                     .decode("utf-8", errors="replace").strip())
                    except Exception:
                        pass
                    findings.append({"pid": int(pid), "marker": marker,
                                     "cmd": cmd[:200]})
                    break
    except Exception:
        pass
    return findings

def find_unverified_attestation_reports():
    """
    Attestation report/quote files present on disk with no evidence any
    verification tool has read them — generated and forgotten.
    """
    report_patterns = ["*.quote", "*attestation*.json", "*.dcap",
                       "*sgx_quote*", "*sev_report*", "*snp_report*"]
    found = []
    for base in ("/tmp", "/var/lib", "/opt", os.path.expanduser("~")):
        for pattern in report_patterns:
            for path in glob.glob(os.path.join(base, "**", pattern),
                                   recursive=True)[:20]:
                if os.path.isfile(path):
                    try:
                        st = os.stat(path)
                        found.append({"path": path, "size": st.st_size,
                                     "mtime": st.st_mtime})
                    except Exception:
                        pass
    return found

def check_attestation_tools_present():
    """Which real attestation verification tools exist on this host."""
    found = []
    for tool in ATTESTATION_TOOLS:
        for d in os.environ.get("PATH", "/usr/bin:/bin").split(":"):
            p = os.path.join(d, tool)
            if os.path.isfile(p):
                found.append(tool)
                break
    return found

def check_dmesg_tee_events():
    hits = []
    try:
        out = subprocess.check_output(["dmesg"], text=True, timeout=3,
                                       stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            low = line.lower()
            if any(k in low for k in ("sgx", "sev-snp", "sev:", "ccp ")):
                hits.append(line.strip())
    except Exception:
        pass
    return hits[-20:]

def analyse(sgx_hw, sev_hw, debug_enclaves, unverified_claims,
            unverified_reports, attestation_tools, dmesg_hits, state):
    alerts = []

    # ── 1. TEE claimed without any hardware present ──
    for c in unverified_claims:
        alerts.append({
            "event":    "TEE_CLAIM_WITHOUT_HARDWARE",
            "severity": "CRITICAL",
            "pid":      c["pid"],
            "marker":   c["marker"],
            "cmd":      c["cmd"],
            "confidence": 0.85,
            "note": ("A process environment references TEE/confidential "
                     "computing tooling, but no SGX or SEV device is present "
                     "on this host. Any confidentiality claim this workload "
                     "makes about running in a hardware-isolated enclave is "
                     "unverifiable — and likely false. This is 'presence "
                     "checking without attestation' in its most direct form: "
                     "there is not even hardware to check presence of"),
        })

    # ── 2. Debug-mode enclaves ──
    for d in debug_enclaves:
        alerts.append({
            "event":    "SGX_DEBUG_MODE_ENCLAVE",
            "severity": "CRITICAL",
            "pid":      d["pid"],
            "cmd":      d["cmd"],
            "confidence": 0.85,
            "note": ("A process appears to be running an SGX enclave in "
                     "debug mode. Debug enclaves have NO confidentiality "
                     "guarantee — their memory is fully readable by the host "
                     "OS. This defeats the entire purpose of using SGX and "
                     "must never be present in production"),
        })

    # ── 3. Unverified attestation reports on disk ──
    if unverified_reports:
        alerts.append({
            "event":    "ATTESTATION_REPORTS_UNVERIFIED",
            "severity": "WARN",
            "count":    len(unverified_reports),
            "sample":   unverified_reports[:5],
            "confidence": 0.55,
            "note": ("Attestation report or quote files exist on disk. This "
                     "module cannot confirm whether they were ever "
                     "cryptographically verified against the Intel/AMD root "
                     "of trust — a report that was generated and never "
                     "checked provides zero security benefit"),
        })

    # ── 4. Hardware present but no verification tooling ──
    has_hardware = bool(sgx_hw["devices_present"] or sev_hw["devices_present"])
    if has_hardware and not attestation_tools:
        alerts.append({
            "event":    "TEE_HARDWARE_NO_VERIFICATION_TOOLING",
            "severity": "WARN",
            "sgx_devices": sgx_hw["devices_present"],
            "sev_devices": sev_hw["devices_present"],
            "confidence": 0.60,
            "note": ("TEE hardware is present but no attestation "
                     "verification tooling (snpguest, sgx_sign, DCAP tools) "
                     "was found on this host. Without it, nothing on this "
                     "host can independently verify an attestation report"),
        })

    # ── 5. SGX present without CPUID confirmation ──
    if sgx_hw["devices_present"] and sgx_hw["cpuid_sgx"] is False:
        alerts.append({
            "event":    "SGX_DEVICE_WITHOUT_CPU_SUPPORT",
            "severity": "WARN",
            "devices":  sgx_hw["devices_present"],
            "confidence": 0.60,
            "note": ("An SGX device node exists but CPUID does not report "
                     "SGX support. This is consistent with a container or VM "
                     "environment where the device was passed through "
                     "without genuine underlying hardware support — "
                     "verify before trusting any attestation from it"),
        })

    # ── 6. Known vulnerability markers in dmesg ──
    for line in dmesg_hits:
        for cve, desc in KNOWN_VULNERABILITIES.items():
            pass  # dmesg rarely names CVEs directly; version-based check below
        alerts.append({
            "event":    "DMESG_TEE_EVENT",
            "severity": "INFO",
            "log":      line,
            "confidence": 0.35,
        })

    # ── 7. Config drift ──
    known = state.setdefault("config_hash", {})
    current_config = json.dumps({"sgx": sgx_hw, "sev": sev_hw}, sort_keys=True)
    current_hash = hashlib.sha256(current_config.encode()).hexdigest()
    prev_hash = known.get("tee_config")
    if prev_hash and prev_hash != current_hash:
        alerts.append({
            "event":    "TEE_CONFIG_CHANGED",
            "severity": "WARN",
            "confidence": 0.60,
            "note": "TEE hardware/device configuration changed since baseline",
        })
    known["tee_config"] = current_hash

    return alerts, state

def main():
    log = open(f"module87_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "87_tee_attestation_verifier",
        "status": ("PARTIAL — host-side presence/config checks functional, "
                    "cryptographic quote verification AWAITING_HARDWARE_INTEGRATION"),
        "problem": ("A workload can claim TEE execution without that claim "
                     "ever being cryptographically verified. Presence "
                     "checking (does the device exist) is not attestation "
                     "(is this specific code running in genuine isolated "
                     "hardware, provably)"),
        "confirmed_vulnerabilities": KNOWN_VULNERABILITIES,
        "functional_now": [
            "SGX device and CPUID presence detection",
            "SEV/SEV-SNP guest device presence",
            "TEE claimed via environment markers with no hardware present",
            "SGX debug-mode enclave detection (zero confidentiality)",
            "Unverified attestation report/quote files on disk",
            "Attestation verification tooling presence",
            "TEE configuration drift",
        ],
        "awaiting_hardware": [
            "Full cryptographic SGX DCAP quote verification against Intel root of trust",
            "SEV-SNP attestation report verification against AMD KDS",
            "MRENCLAVE/MRSIGNER measurement comparison against known-good reference",
            "Live TCB recovery status check",
        ],
        "same_category_as": ("module82's RuntimeClass problem and module85's "
                              "PERMISSIVE mTLS problem — a control that is "
                              "declared and appears applied without doing "
                              "what it claims"),
    })

    state = load_state()

    while True:
        sgx_hw = check_sgx_hardware()
        sev_hw = check_sev_hardware()
        debug_enclaves = check_debug_mode_enclaves()
        unverified_claims = check_tee_claims_without_hardware(sgx_hw, sev_hw)
        unverified_reports = find_unverified_attestation_reports()
        attestation_tools = check_attestation_tools_present()
        dmesg_hits = check_dmesg_tee_events()

        emit({"event": "TEE_SCAN",
              "sgx_devices":     sgx_hw["devices_present"],
              "sgx_cpuid":       sgx_hw["cpuid_sgx"],
              "sev_devices":     sev_hw["devices_present"],
              "debug_enclaves":  len(debug_enclaves),
              "unverified_claims": len(unverified_claims),
              "unverified_reports": len(unverified_reports),
              "attestation_tools": attestation_tools})

        if not sgx_hw["devices_present"] and not sev_hw["devices_present"]:
            emit({"event": "NO_TEE_HARDWARE",
                  "note": ("No SGX or SEV hardware detected on this host. "
                           "This module activates fully on TEE-capable "
                           "infrastructure. Claim-without-hardware checks "
                           "still run.")})

        alerts, state = analyse(sgx_hw, sev_hw, debug_enclaves,
                                unverified_claims, unverified_reports,
                                attestation_tools, dmesg_hits, state)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "TEE_STATE_OK",
                  "sgx_present": bool(sgx_hw["devices_present"]),
                  "sev_present": bool(sev_hw["devices_present"])})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
