#!/usr/bin/env python3
"""
Append tests for modules 22-50 to test_b200_watchdog.py.
Run from ~/Watchdog: python3 ~/storage/downloads/step2_add_tests.py
"""
import os, sys

TEST_FILE = os.path.expanduser("~/Watchdog/todo/test_b200_watchdog.py")

NEW_TESTS = '''
# ═══════════════════════════════════════
# MODULE 22 — PCIe Link Guard
# ═══════════════════════════════════════
section("module22.py — PCIe Link Guard")
import module22
test("PCIE_EXPECTED = 32.0 GT/s (Gen5)", lambda: module22.PCIE_EXPECTED == 32.0)
test("DROP_LIMIT = 2 generations", lambda: module22.DROP_LIMIT == 2)
test("DROP_WINDOW = 1.0s", lambda: module22.DROP_WINDOW == 1.0)
test("speed_to_gen(32.0) = 5", lambda: module22.speed_to_gen(32.0) == 5)
test("speed_to_gen(64.0) = 6", lambda: module22.speed_to_gen(64.0) == 6)
test("retrain uses setpci", lambda: "setpci" in inspect.getsource(module22.retrain_link))

# ═══════════════════════════════════════
# MODULE 23 — Cache Noise Injector
# ═══════════════════════════════════════
section("module23.py — Cache Noise Injector")
import module23
test("CV_THRESHOLD = 0.15", lambda: module23.CV_THRESHOLD == 0.15)
test("LAG1_AC_THRESH = 0.50", lambda: module23.LAG1_AC_THRESH == 0.50)
test("No random() in is_periodic", lambda: "random" not in inspect.getsource(module23.is_periodic))
test("WINDOW_SIZE >= 10", lambda: module23.WINDOW_SIZE >= 10)
test("thrash uses stress-ng not dd", lambda: "stress-ng" in inspect.getsource(module23.thrash_cache_stressng))
test("is_periodic returns False on uniform samples", lambda: not module23.is_periodic([1000]*5)[0])

# ═══════════════════════════════════════
# MODULE 24 — ACPI Power Guard
# ═══════════════════════════════════════
section("module24.py — ACPI Power Guard")
import module24
test("ACPI_THRESHOLD = 3", lambda: module24.ACPI_THRESHOLD == 3)
test("ACPI_WINDOW = 60s", lambda: module24.ACPI_WINDOW == 60)
test("ACPI patterns defined", lambda: len(module24.ACPI_PATTERNS) > 0)
test("disable_acpi uses /sys/class/power_supply", lambda: "power_supply" in inspect.getsource(module24.disable_acpi_power_source))
test("IPMI fallback present", lambda: "ipmitool" in inspect.getsource(module24.ipmi_lock_psu))

# ═══════════════════════════════════════
# MODULE 25 — Boot Hash Guard
# ═══════════════════════════════════════
section("module25.py — Boot Hash Guard")
import module25
test("SHA256 used for hashing", lambda: "sha256" in inspect.getsource(module25.sha256_file).lower())
test("initrd paths defined", lambda: len(module25.INITRD_PATHS) > 0)
test("POLL_INTERVAL = 60s", lambda: module25.POLL_INTERVAL == 60)
test("firmware reboot is opt-in", lambda: module25.FIRMWARE_REBOOT == False)
test("resolve_initrd_paths scans /boot", lambda: "/boot" in inspect.getsource(module25.resolve_initrd_paths))

# ═══════════════════════════════════════
# MODULE 26 — GDS VRAM Guard
# ═══════════════════════════════════════
section("module26.py — GDS VRAM Guard")
import module26
test("checks nvidia-peermem first", lambda: "nvidia_peermem" in inspect.getsource(module26.check_nvme_gds_mapping))
test("IOMMU group scan present", lambda: "iommu_groups" in inspect.getsource(module26.check_iommu_nvme_gpu_mapping))
test("unbind uses NVMe driver path", lambda: "nvme" in inspect.getsource(module26.unbind_nvme))
test("POLL_INTERVAL defined", lambda: hasattr(module26, "POLL_INTERVAL"))

# ═══════════════════════════════════════
# MODULE 32 — PQC Crypto Readiness
# ═══════════════════════════════════════
section("module32.py — PQC Crypto Readiness")
import module32
test("Quantum-vulnerable algorithms listed", lambda: len(module32.QUANTUM_VULNERABLE) > 0)
test("ssh-rsa in vulnerable list", lambda: "ssh-rsa" in module32.QUANTUM_VULNERABLE)
test("PQC safe indicators defined", lambda: len(module32.PQC_SAFE_INDICATORS) > 0)
test("sntrup761 in PQC indicators", lambda: "sntrup761" in module32.PQC_SAFE_INDICATORS)
test("check_ssh_host_keys scans /etc/ssh", lambda: "/etc/ssh" in inspect.getsource(module32.check_ssh_host_keys))
test("WEAK_RSA_BITS = 3072", lambda: module32.WEAK_RSA_BITS == 3072)

# ═══════════════════════════════════════
# MODULE 33 — QaaS API Integrity
# ═══════════════════════════════════════
section("module33.py — QaaS API Integrity")
import module33
test("hash_circuit uses SHA256", lambda: "sha256" in inspect.getsource(module33.hash_circuit).lower())
test("hash_circuit is deterministic", lambda: module33.hash_circuit({"a":1}) == module33.hash_circuit({"a":1}))
test("RESPONSE_SPIKE threshold defined", lambda: hasattr(module33, "RESPONSE_SPIKE"))
test("IBM API URL correct", lambda: "quantum-computing.ibm.com" in module33.IBM_QUANTUM_API)
test("graceful fallback if no token", lambda: "no_credentials" in inspect.getsource(module33.main))

# ═══════════════════════════════════════
# MODULE 34 — QPU Calibration Drift
# ═══════════════════════════════════════
section("module34.py — QPU Calibration Drift")
import module34
test("T1_DROP_THRESHOLD = 0.50", lambda: module34.T1_DROP_THRESHOLD == 0.50)
test("T2_DROP_THRESHOLD = 0.50", lambda: module34.T2_DROP_THRESHOLD == 0.50)
test("BASELINE_SAMPLES defined", lambda: hasattr(module34, "BASELINE_SAMPLES"))
test("uses backend.properties(refresh=True)", lambda: "refresh=True" in inspect.getsource(module34.fetch_backend_properties))
test("graceful fallback if no token", lambda: "NO_CREDENTIALS" in inspect.getsource(module34.main))

# ═══════════════════════════════════════
# MODULE 35 — Qubit Error Rate Anomaly
# ═══════════════════════════════════════
section("module35.py — Qubit Error Rate Anomaly")
import module35
test("ERROR_SPIKE_MULT = 5.0", lambda: module35.ERROR_SPIKE_MULT == 5.0)
test("ERROR_SPIKE_MIN = 3 qubits", lambda: module35.ERROR_SPIKE_MIN == 3)
test("No random() in detect_anomalies", lambda: "random" not in inspect.getsource(module35.detect_anomalies))
test("EMA baseline update (alpha)", lambda: "alpha" in inspect.getsource(module35.update_baseline))
test("graceful fallback if no token", lambda: "NO_CREDENTIALS" in inspect.getsource(module35.main))

# ═══════════════════════════════════════
# MODULES 36-39 — Physical Stubs
# ═══════════════════════════════════════
section("module36-39.py — Physical Hardware Stubs")
import module36, module37, module38, module39
test("module36 is AWAITING_HARDWARE_INTEGRATION", lambda: "AWAITING_HARDWARE_INTEGRATION" in inspect.getsource(module36.main))
test("module37 FPGA PCIe scan runs now", lambda: "scan_fpga_pcie" in inspect.getsource(module37))
test("module37 FPGA vendor IDs defined", lambda: len(module37.FPGA_VENDOR_IDS) > 0)
test("module38 vacuum stub has no sensor code", lambda: "serial" not in inspect.getsource(module38.main).lower())
test("module39 helium stub has cost context", lambda: "50" in inspect.getsource(module39.main))

# ═══════════════════════════════════════
# MODULE 40 — QaaS Replay Prevention
# ═══════════════════════════════════════
section("module40.py — QaaS API Replay")
import module40
test("generate_nonce uses secrets", lambda: "secrets" in inspect.getsource(module40.generate_nonce))
test("NONCE_EXPIRY_S = 3600", lambda: module40.NONCE_EXPIRY_S == 3600)
test("check_replay returns False for new nonce", lambda: not module40.check_replay("abc123", {}))
test("check_replay returns True for seen nonce", lambda: module40.check_replay("abc123", {"abc123": 1234567890}))
test("nonces pruned on save", lambda: "NONCE_EXPIRY" in inspect.getsource(module40.save_nonces))

# ═══════════════════════════════════════
# MODULE 41 — Qubit Calibration DDoS
# ═══════════════════════════════════════
section("module41.py — Qubit Calibration DDoS")
import module41
test("DDOS_THRESHOLD = 3", lambda: module41.DDOS_THRESHOLD == 3)
test("DDOS_WINDOW_S = 600s", lambda: module41.DDOS_WINDOW_S == 600)
test("cannot block from userspace — logs to IBM support", lambda: "Report to IBM" in inspect.getsource(module41.detect_qubit_ddos))
test("graceful fallback if no token", lambda: "NO_CREDENTIALS" in inspect.getsource(module41.main))

# ═══════════════════════════════════════
# MODULE 42 — Queue Front-Running
# ═══════════════════════════════════════
section("module42.py — Queue Front-Running")
import module42
test("DEVIATION_SIGMA = 3.0", lambda: module42.DEVIATION_SIGMA == 3.0)
test("TIMING_WINDOW = 20 jobs", lambda: module42.TIMING_WINDOW == 20)
test("mean_std returns None for <2 values", lambda: module42.mean_std([5]) == (None, None))
test("mean_std correct for known values", lambda: abs(module42.mean_std([1,3])[0] - 2.0) < 0.001)
test("graceful fallback if no token", lambda: "NO_CREDENTIALS" in inspect.getsource(module42.main))

# ═══════════════════════════════════════
# MODULE 43 — Crypto Downgrade Prevention
# ═══════════════════════════════════════
section("module43.py — Crypto Downgrade Prevention")
import module43
test("QUANTUM_VULNERABLE_KEX defined", lambda: len(module43.QUANTUM_VULNERABLE_KEX) > 0)
test("ecdh algorithms in vulnerable list", lambda: any("ecdh" in a for a in module43.QUANTUM_VULNERABLE_KEX))
test("PQC_SAFE_KEX = sntrup761", lambda: "sntrup761" in module43.PQC_SAFE_KEX)
test("hardening is opt-in (disabled by default)", lambda: module43.ENABLE_HARDENING == False)
test("backup created before modifying sshd", lambda: "SSHD_BACKUP_PATH" in inspect.getsource(module43.harden_sshd))

# ═══════════════════════════════════════
# MODULE 44 — Cryogenic Power Spike
# ═══════════════════════════════════════
section("module44.py — Power Spike Detection")
import module44
test("SPIKE_MULTIPLIER = 2.0", lambda: module44.SPIKE_MULTIPLIER == 2.0)
test("SPIKE_DURATION_S = 5.0", lambda: module44.SPIKE_DURATION_S == 5.0)
test("RAPL powercap path defined", lambda: "powercap" in module44.POWERCAP_BASE)
test("TPM write present", lambda: "tpm2_nvwrite" in inspect.getsource(module44.write_to_tpm))
test("IPMI fallback present", lambda: "ipmitool" in inspect.getsource(module44.read_ipmi_power))

# ═══════════════════════════════════════
# MODULE 45 — Credential Drain
# ═══════════════════════════════════════
section("module45.py — Credential Drain")
import module45
test("MAX_SHOTS_PER_HOUR = 100000", lambda: module45.MAX_SHOTS_PER_HOUR == 100_000)
test("MAX_JOBS_PER_HOUR = 200", lambda: module45.MAX_JOBS_PER_HOUR == 200)
test("DRAIN_WINDOW_S = 3600s", lambda: module45.DRAIN_WINDOW_S == 3600)
test("no auto key rotation (manual action)", lambda: "Rotate" in inspect.getsource(module45.detect_credential_drain))
test("graceful fallback if no token", lambda: "NO_CREDENTIALS" in inspect.getsource(module45.main))

# ═══════════════════════════════════════
# MODULE 46 — Annealer Side-Channel
# ═══════════════════════════════════════
section("module46.py — Annealer Side-Channel")
import module46
test("PERIODIC_CV_THRESH = 0.15", lambda: module46.PERIODIC_CV_THRESH == 0.15)
test("LAG1_AC_THRESH = 0.50", lambda: module46.LAG1_AC_THRESH == 0.50)
test("No random() in is_periodic", lambda: "random" not in inspect.getsource(module46.is_periodic))
test("lag1 autocorr of constant = 0", lambda: module46.lag1_autocorr([5,5,5,5,5]) == 0.0)
test("noise job uses randomized timing", lambda: "random" in inspect.getsource(module46.inject_noise_job))
test("graceful fallback if no token", lambda: "NO_CREDENTIALS" in inspect.getsource(module46.main))

# ═══════════════════════════════════════
# MODULE 47 — Supply Chain Integrity
# ═══════════════════════════════════════
section("module47.py — Supply Chain Integrity")
import module47
test("qiskit in packages to check", lambda: "qiskit" in module47.PACKAGES_TO_CHECK)
test("cirq in packages to check", lambda: "cirq" in module47.PACKAGES_TO_CHECK)
test("SHA256 used for hashing", lambda: "sha256" in inspect.getsource(module47.hash_package_files).lower())
test("no auto-delete (flags only)", lambda: "flag" in inspect.getsource(module47).lower() or "Rotate" in inspect.getsource(module47))
test("PyPI API used for verification", lambda: "pypi.org" in inspect.getsource(module47.get_pypi_hash))

# ═══════════════════════════════════════
# MODULE 48 — Quantum Cost Drain
# ═══════════════════════════════════════
section("module48.py — Quantum Cost Drain")
import module48
test("COST_SPIKE_MULT = 3.0", lambda: module48.COST_SPIKE_MULT == 3.0)
test("ECONOMICS_AVAILABLE is bool", lambda: isinstance(module48.ECONOMICS_AVAILABLE, bool))
test("quantum_models path wired", lambda: "_QM_PATH" in inspect.getsource(module48))
test("graceful fallback if model missing", lambda: "MODEL_NOT_AVAILABLE" in inspect.getsource(module48.main))

# ═══════════════════════════════════════
# MODULE 49 — Fleet Efficiency Anomaly
# ═══════════════════════════════════════
section("module49.py — Fleet Efficiency Anomaly")
import module49
test("SCORE_DROP_THRESHOLD = 0.20", lambda: module49.SCORE_DROP_THRESHOLD == 0.20)
test("FLEET_AVAILABLE is bool", lambda: isinstance(module49.FLEET_AVAILABLE, bool))
test("quantum_models path wired", lambda: "_QM_PATH" in inspect.getsource(module49))
test("reference backends defined", lambda: "ibm_brisbane" in inspect.getsource(module49.get_backend_fleet_scores))
test("graceful fallback if model missing", lambda: "MODEL_NOT_AVAILABLE" in inspect.getsource(module49.main))

# ═══════════════════════════════════════
# MODULE 50 — Load Balancer Guard
# ═══════════════════════════════════════
section("module50.py — Load Balancer Guard")
import module50
test("HOTSPOT_THRESHOLD = 0.70", lambda: module50.HOTSPOT_THRESHOLD == 0.70)
test("LB_AVAILABLE is bool", lambda: isinstance(module50.LB_AVAILABLE, bool))
test("quantum_models path wired", lambda: "_QM_PATH" in inspect.getsource(module50))
test("detect_hotspot returns empty on low job count", lambda: module50.detect_hotspot({"a": {"pending_jobs": 2}, "b": {"pending_jobs": 1}}) == [])
test("graceful fallback if no token", lambda: "NO_CREDENTIALS" in inspect.getsource(module50.main))

# ═══════════════════════════════════════
# MODULE 21 — Quantum wiring verification
# ═══════════════════════════════════════
section("module21.py — Quantum model wiring")
import module21
test("quantum_models path wired into module21", lambda: "_QM_PATH" in inspect.getsource(module21))
test("QUANTUM_MODELS_AVAILABLE is bool", lambda: isinstance(module21.QUANTUM_MODELS_AVAILABLE, bool))
test("get_quantum_efficiency_snapshot defined", lambda: callable(module21.get_quantum_efficiency_snapshot))
test("QPU attack vectors in threat matrix", lambda: any("QUBIT" in str(k) for k in module21.THREAT_MATRIX))
test("QaaS attacks in threat matrix", lambda: any("QAAS" in str(k) for k in module21.THREAT_MATRIX))
test("compliance claims include qpu_attacks", lambda: any(c["type"] == "no_qpu_attacks" for c in module21.CLAIMS))
'''

def main():
    if not os.path.exists(TEST_FILE):
        print(f"ERROR: {TEST_FILE} not found")
        sys.exit(1)

    with open(TEST_FILE) as f:
        content = f.read()

    # Find the SUMMARY block and insert before it
    summary_marker = "# SUMMARY"
    if summary_marker not in content:
        summary_marker = "passed = sum"

    if summary_marker not in content:
        print("ERROR: Cannot find summary block in test file")
        sys.exit(1)

    new_content = content.replace(summary_marker, NEW_TESTS + "\n" + summary_marker)

    with open(TEST_FILE, "w") as f:
        f.write(new_content)

    print(f"Patched {TEST_FILE}")
    print(f"Added ~{NEW_TESTS.count('test(')} new tests")

if __name__ == "__main__":
    main()
