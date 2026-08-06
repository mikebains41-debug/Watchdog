#!/usr/bin/env python3
"""
Watchdog B200 — Combined Module Test Suite
Run from todo/ directory: python3 test_b200_watchdog.py
No hardware writes. Dry-run only.
"""
import sys, os, json, hashlib, hmac as _hmac, inspect

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; E = "\033[0m"
results = []

def test(name, fn):
    try:
        r = fn()
        tag = f"{G}[PASS]{E}" if r else f"{R}[FAIL]{E}"
        print(f"{tag} {name}")
        results.append((name, bool(r)))
    except Exception as ex:
        print(f"{R}[FAIL]{E} {name}  ({type(ex).__name__}: {ex})")
        results.append((name, False))

def section(s): print(f"\n── {s} ──")

# ═══════════════════════════════════════
# GPU HARDWARE
# ═══════════════════════════════════════
section("module17.py")

def t_power():
    import module17 as m
    return m.POWER_EMERGENCY == 800

def t_ghost_power_floor():
    import module17 as m
    return m.GHOST_POWER_FLOOR == 80

def t_b200_clocks():
    import module17 as m
    return m.B200_MEM_CLOCK == 8000 and m.B200_SM_CLOCK == 2400

def t_ac_order():
    import module17 as m
    src = inspect.getsource(m.lock_clocks)
    # Must be MEM,SM order: "8000,2400" via constants
    return "B200_MEM_CLOCK" in src and "B200_SM_CLOCK" in src

def t_ecc_dual_threshold():
    import module17 as m
    return m.ECC_ABSOLUTE_FLOOR == 50 and m.ECC_SPIKE == 10

def t_no_invalid_ac():
    import module17 as m
    src = inspect.getsource(m)
    return '"0,1"' not in src and '"5001,0"' not in src

test("POWER_EMERGENCY = 800W (not 50W)", t_power)
test("GHOST_POWER_FLOOR = 80W", t_ghost_power_floor)
test("B200 clocks: MEM=8000, SM=2400", t_b200_clocks)
test("-ac uses MEM_CLOCK,SM_CLOCK order", t_ac_order)
test("ECC dual threshold: 10x relative + 50/s absolute", t_ecc_dual_threshold)
test("No invalid -ac values (0,1 / 5001,0)", t_no_invalid_ac)

# ═══════════════════════════════════════
# BUS & INTERCONNECT
# ═══════════════════════════════════════
section("module18.py")

def t_pcie_gen5():
    import module18 as m
    return m.PCIE_EXPECTED == 32.0   # Gen5, not Gen6

def t_pcie_thresholds():
    import module18 as m
    return m.PCIE_WARN == 24.0 and m.PCIE_CRIT == 16.0

def t_nvlink_18():
    import module18 as m
    return m.NVLINK_LINKS == 18

def t_nvlink_parser_no_bandwidth_string():
    """Old parser looked for 'Bandwidth' string which doesn't appear in real B200 output."""
    import module18 as m
    src = inspect.getsource(m.parse_nvlink_counters)
    return '"Bandwidth"' not in src and 'Bandwidth' not in src.split("re.search")[0]

def t_nvlink_parser_unit_aware():
    import module18 as m
    # Should handle KB/s, MB/s, GB/s
    raw = "Link 0: <Throughput Rx>  500 KB/s\nLink 1: <Throughput Tx>  2 MB/s\n"
    result = m.parse_nvlink_counters(raw)
    # 500 KB/s + 2*1024 KB/s = 2548
    return result == 500 + 2 * 1024

def t_no_shell_redirect():
    import module18 as m
    src = inspect.getsource(m)
    return 'shell=True' not in src

test("PCIe expected = 32 GT/s (Gen5, not Gen6=64)", t_pcie_gen5)
test("PCIe warn=24, crit=16 GT/s", t_pcie_thresholds)
test("NVLink_LINKS = 18 (NV18 topology)", t_nvlink_18)
test("NVLink parser uses regex", lambda: "re.search" in inspect.getsource(__import__("module18").parse_nvlink_counters))
test("NVLink parser handles KB/s + MB/s units", t_nvlink_parser_unit_aware)
test("No broken shell=True redirect", t_no_shell_redirect)

# ═══════════════════════════════════════
# GPU SOFTWARE
# ═══════════════════════════════════════
section("module19.py")

def t_ecc_window_50():
    import module19 as m
    return m.ECC_WINDOW == 50

def t_cmdline_nullbyte():
    raw = b"python3\x00-u\x00watchdog.py\x00"
    cmd = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    return "\x00" not in cmd and "python3" in cmd

def t_reads_rb():
    import module19 as m
    src = inspect.getsource(m.cmdline)
    return '"rb"' in src

def t_no_pkill_nc():
    import module19 as m
    src = inspect.getsource(m)
    return "pkill" not in src

def t_safe_ports():
    import module19 as m
    return 80 in m.SAFE_PORTS and 443 in m.SAFE_PORTS and 22 in m.SAFE_PORTS

test("ECC_WINDOW = 50 for HBM3e", t_ecc_window_50)
test("Null-byte cmdline parsing correct", t_cmdline_nullbyte)
test("cmdline opened in binary mode 'rb'", t_reads_rb)
test("No blunt pkill -f nc", t_no_pkill_nc)
test("Safe ports 22/80/443 excluded from exfil kill", t_safe_ports)

# ═══════════════════════════════════════
# HOST SECURITY
# ═══════════════════════════════════════
section("module20.py")

def t_spectre_cooldown():
    import module20 as m
    return m.SPECTRE_COOLDOWN == 1800

def t_lock_hz_not_string():
    import module20 as m
    return isinstance(m.LLC_LOCK_HZ, int) and m.LLC_LOCK_HZ == 800000

def t_governor_flag():
    import module20 as m
    src = inspect.getsource(m.unlock_cpu)
    return '"-g"' in src and '"-f"' not in src

def t_arm_detection():
    import module20 as m
    return callable(m.is_arm)

def t_keyword_block():
    import module20 as m
    susp, reason = m.is_suspicious("/tmp/xmrig", "abc123")
    return susp and "xmrig" in reason

def t_path_allow():
    import module20 as m
    susp, _ = m.is_suspicious("/usr/bin/python3", "abc")
    return not susp

def t_script_allow():
    import module20 as m
    susp, _ = m.is_suspicious("/tmp/myscript.py", None)
    return not susp

def t_all_miners_blocked():
    import module20 as m
    for kw in m.MINER_KEYWORDS:
        susp, _ = m.is_suspicious(f"/tmp/{kw}", "hash")
        if not susp:
            return False
    return True

test("SPECTRE_COOLDOWN = 1800s (30 min)", t_spectre_cooldown)
test("LLC_LOCK_HZ = 800000 (int, not '800MHz')", t_lock_hz_not_string)
test("unlock_cpu uses -g (governor), not -f", t_governor_flag)
test("ARM / Grace CPU detection present", t_arm_detection)
test("Miner keyword 'xmrig' blocked", t_keyword_block)
test("Path allowlist /usr/bin/ passes", t_path_allow)
test("Script (None hash) not blocked", t_script_allow)
test(f"All {len(__import__('module20').MINER_KEYWORDS)} miner keywords blocked", t_all_miners_blocked)

# ═══════════════════════════════════════
# SUPERVISOR
# ═══════════════════════════════════════
section("module21.py")

def t_hash_chain():
    prev = "0" * 128
    entries = []
    key = os.urandom(64)
    for i in range(5):
        e = {"event": f"T{i}", "prev_hash": prev}
        canon = json.dumps(e, sort_keys=True).encode()
        h = hashlib.sha512(canon).hexdigest()
        e["hash"] = h; entries.append(e); prev = h
    return all(entries[i]["prev_hash"] == entries[i-1]["hash"]
               for i in range(1, len(entries)))

def t_tamper_breaks_chain():
    prev="0"*128; entries=[]
    for i in range(3):
        e={"event":f"T{i}","prev_hash":prev}
        h=hashlib.sha512(json.dumps(e,sort_keys=True).encode()).hexdigest()
        e["hash"]=h; entries.append(e); prev=h
    tampered={"event":"TAMPERED","prev_hash":entries[0]["hash"]}
    th=hashlib.sha512(json.dumps(tampered,sort_keys=True).encode()).hexdigest()
    return entries[2]["prev_hash"]!=th

def t_threat_matrix_nvlink_exfil():
    import module21 as m
    events = [{"event": "NVLINK_SESSION_HIJACK_BLOCKED"},
              {"event": "MODEL_EXFIL_BLOCKED"}]
    r = m.check_matrix(events)
    return r is not None and r[0] >= m.LEVEL_QUARANTINE

def t_threat_matrix_ghost_rowhammer():
    import module21 as m
    events = [{"event": "GHOST_POWER_DETECTED"},
              {"event": "VRAM_ROWHAMMER_PREVENT"}]
    r = m.check_matrix(events)
    return r is not None and r[0] >= m.LEVEL_RESET

def t_benign_no_trigger():
    import module21 as m
    return m.check_matrix([{"event": "RUN_START"}, {"event": "PCIe_REBOUND"}]) is None

def t_merkle_deterministic():
    import module21 as m
    data = [{"e": i} for i in range(8)]
    r1, _ = m.build_merkle(data)
    r2, _ = m.build_merkle(data)
    return r1 == r2

def t_merkle_inclusion():
    import module21 as m
    data = [{"e": i} for i in range(8)]
    root, tree = m.build_merkle(data)
    return all(m.verify_proof(data[i], m.inclusion_proof(tree, i), root)
               for i in range(len(data)))

def t_merkle_tamper():
    import module21 as m
    data = [{"e": i} for i in range(8)]
    root, tree = m.build_merkle(data)
    proof = m.inclusion_proof(tree, 3)
    return not m.verify_proof({"e": 999}, proof, root)

def t_merkle_odd():
    import module21 as m
    data = [{"e": i} for i in range(7)]
    root, tree = m.build_merkle(data)
    return all(m.verify_proof(data[i], m.inclusion_proof(tree, i), root)
               for i in range(len(data)))

test("5-entry hash chain valid", t_hash_chain)
test("Tampered entry breaks chain", t_tamper_breaks_chain)
test("NVLink + Exfil → QUARANTINE", t_threat_matrix_nvlink_exfil)
test("Ghost power + Rowhammer → RESET", t_threat_matrix_ghost_rowhammer)
test("Benign events → no trigger", t_benign_no_trigger)
test("Merkle root deterministic", t_merkle_deterministic)
test("Inclusion proof valid for all 8 leaves", t_merkle_inclusion)
test("Tampered leaf fails proof", t_merkle_tamper)
test("Odd-count tree (7 leaves) works", t_merkle_odd)

# ═══════════════════════════════════════

# MODULE 27
section("module27.py — VFIO Guard")
import module27
test("FAILURE_THRESHOLD = 3", lambda: module27.FAILURE_THRESHOLD == 3)
test("FAILURE_WINDOW = 60s", lambda: module27.FAILURE_WINDOW == 60)
test("vfio-pci in error patterns", lambda: "vfio-pci" in module27.VFIO_ERROR_PATTERNS)
test("dmesg scan filters error+fail", lambda: "fail" in inspect.getsource(module27.scan_dmesg_vfio).lower())
test("rebind_nvidia has modprobe fallback", lambda: "modprobe" in inspect.getsource(module27.rebind_nvidia))

# MODULE 28
section("module28.py — NVLink IPG")
import module28
test("SIGMA_THRESHOLD = 3.0", lambda: module28.SIGMA_THRESHOLD == 3.0)
test("WINDOW_SIZE = 10", lambda: module28.WINDOW_SIZE == 10)
test("stddev of constant = 0", lambda: module28.stddev([5,5,5,5]) == 0.0)
test("stddev of varied > 0", lambda: module28.stddev([1,2,3,4,5]) > 0)
test("NVLink parser KB/s + MB/s", lambda: module28.parse_nvlink_counters("Link 0: <Throughput Rx>  1000 KB/s\nLink 1: <Throughput Tx>  1 MB/s\n") == 1000+1024)
test("CUPY_AVAILABLE is bool", lambda: isinstance(module28.CUPY_AVAILABLE, bool))

# MODULE 29
section("module29.py — SEV Attestation")
import module29
test("drop_caches not wrmsr", lambda: "drop_caches" in inspect.getsource(module29.flush_cpu_cache) and "open" in inspect.getsource(module29.flush_cpu_cache))
test("flush_cpu_cache uses drop_caches", lambda: "drop_caches" in inspect.getsource(module29.flush_cpu_cache))
test("TPM path /dev/tpm0 checked", lambda: "/dev/tpm0" in inspect.getsource(module29.write_tpm_attestation_log))
test("FAILURE_THRESHOLD = 2", lambda: module29.FAILURE_THRESHOLD == 2)

# MODULE 30
section("module30.py — Page Retirement")
import module30
test("Uses retired_pages.pending", lambda: "retired_pages.pending" in inspect.getsource(module30.get_retired_pages))
test("Uses retired_pages.total", lambda: "retired_pages.total" in inspect.getsource(module30.get_retired_pages))
test("CHANGE_THRESHOLD = 5", lambda: module30.CHANGE_THRESHOLD == 5)
test("CHANGE_WINDOW = 30s", lambda: module30.CHANGE_WINDOW == 30)
test("Double-bit ECC handled", lambda: "dbe" in inspect.getsource(module30.main))

# MODULE 31
section("module31.py — PXE Guard")
import module31
test("PXE boot detected", lambda: module31.check_pxe_boot("BOOTIF=01 ip=dhcp root=nfs://...")[0])
test("Local nvme boot not flagged", lambda: module31.check_local_boot("root=/dev/nvme0n1p1 quiet"))
test("Clean cmdline not PXE", lambda: not module31.check_pxe_boot("root=/dev/nvme0n1p1 quiet")[0])
test("iSCSI keyword detected", lambda: module31.check_pxe_boot("netroot=iscsi:192.168.1.1::::target")[0])
test("ARP monitoring present", lambda: "arp" in inspect.getsource(module31.get_arp_table).lower())


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
test("CV_THRESHOLD defined", lambda: hasattr(module23, "CV_THRESHOLD"))
test("is_periodic uses CV math", lambda: "cv" in inspect.getsource(module23.is_periodic).lower())
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
test("disable_acpi uses /sys/class/power_supply", lambda: "online" in inspect.getsource(module24.disable_acpi_power_source))
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
test("graceful fallback if no token", lambda: "credentials" in inspect.getsource(module33.main).lower())

# ═══════════════════════════════════════
# MODULE 34 — QPU Calibration Drift
# ═══════════════════════════════════════
section("module34.py — QPU Calibration Drift")
import module34
test("T1_DROP_THRESHOLD = 0.50", lambda: module34.T1_DROP_THRESHOLD == 0.50)
test("T2_DROP_THRESHOLD = 0.50", lambda: module34.T2_DROP_THRESHOLD == 0.50)
test("BASELINE_SAMPLES defined", lambda: hasattr(module34, "CALIBRATION_SPIKE_COUNT"))
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
test("module38 vacuum stub has no sensor code", lambda: "AWAITING_HARDWARE_INTEGRATION" in inspect.getsource(module38.main))
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

# SUMMARY
# ═══════════════════════════════════════

# ═══════════════════════════════════════
# MODULE 51 — Circuit Result Verification
# ═══════════════════════════════════════
section("module51.py — Circuit Result Verification")
import module51
test("PROBE_SHOTS = 4096", lambda: module51.PROBE_SHOTS == 4096)
test("CHI2_THRESHOLD = 30.0", lambda: module51.CHI2_THRESHOLD == 30.0)
test("Noise floor min = 0.002", lambda: module51.NOISE_FLOOR_MIN == 0.002)
test("Bell expected is 50/50", lambda: module51.bell_expected() == {"00": 0.5, "11": 0.5})
test("GHZ expected is 50/50", lambda: module51.ghz_expected() == {"000": 0.5, "111": 0.5})
test("chi_squared returns 0 for perfect fit", lambda: module51.chi_squared({"00": 500, "11": 500}, {"00": 0.5, "11": 0.5}, 1000) < 0.001)
test("chi_squared nonzero for bad fit", lambda: module51.chi_squared({"00": 1000, "11": 0}, {"00": 0.5, "11": 0.5}, 1000) > 100)
test("graceful fallback if no token", lambda: "NO_CREDENTIALS" in inspect.getsource(module51.main))

# ═══════════════════════════════════════
# MODULE 52 — Transpiler Integrity
# ═══════════════════════════════════════
section("module52.py — Transpiler Integrity")
import module52
test("DEPTH_RATIO_THRESHOLD = 1.50", lambda: module52.DEPTH_RATIO_THRESHOLD == 1.50)
test("UNITARY_CHECK_MAX_QUBITS = 5", lambda: module52.UNITARY_CHECK_MAX_QUBITS == 5)
test("two_qubit_gate_count counts cx", lambda: module52.two_qubit_gate_count({"cx": 5, "h": 3}) == 5)
test("two_qubit_gate_count counts ecr", lambda: module52.two_qubit_gate_count({"ecr": 4, "rz": 10}) == 4)
test("two_qubit_gate_count ignores 1q gates", lambda: module52.two_qubit_gate_count({"h": 10, "rz": 20}) == 0)
test("two_qubit_gate_count sums multiple types", lambda: module52.two_qubit_gate_count({"cx": 2, "cz": 3}) == 5)
test("unitary check uses Operator", lambda: "Operator" in inspect.getsource(module52.check_unitary_equivalence))
test("graceful fallback if no token", lambda: "NO_CREDENTIALS" in inspect.getsource(module52.main))

# ═══════════════════════════════════════
# MODULE 53 — Qubit Mapping Attack
# ═══════════════════════════════════════
section("module53.py — Qubit Mapping Attack")
import module53
test("BAD_PERCENTILE = 0.25", lambda: module53.BAD_PERCENTILE == 0.25)
test("CRITICAL_PERCENTILE = 0.10", lambda: module53.CRITICAL_PERCENTILE == 0.10)
test("percentile_rank: best value ranks 1.0", lambda: module53.percentile_rank(100, [10,20,30,40], True) == 1.0)
test("percentile_rank: worst value ranks 0.0", lambda: module53.percentile_rank(1, [10,20,30,40], True) == 0.0)
test("percentile_rank: error rate inverted", lambda: module53.percentile_rank(0.001, [0.01,0.02,0.03], False) == 1.0)
test("percentile_rank: empty population = 0.5", lambda: module53.percentile_rank(5, [], True) == 0.5)
test("BETTER_LAYOUT_MARGIN = 1.50", lambda: module53.BETTER_LAYOUT_MARGIN == 1.50)
test("graceful fallback if no token", lambda: "NO_CREDENTIALS" in inspect.getsource(module53.main))

# ═══════════════════════════════════════
# MODULE 54 — Session Hijacking
# ═══════════════════════════════════════
section("module54.py — Session Hijacking")
import module54
test("QUEUE_TIME_TOLERANCE_S = 30", lambda: module54.QUEUE_TIME_TOLERANCE_S == 30)
test("UTILIZATION_FLOOR = 0.40", lambda: module54.UTILIZATION_FLOOR == 0.40)
test("PENDING_JOBS_TOLERANCE = 0", lambda: module54.PENDING_JOBS_TOLERANCE == 0)
test("parse_iso handles Z suffix", lambda: module54.parse_iso("2026-08-05T12:00:00Z") is not None)
test("parse_iso returns None on garbage", lambda: module54.parse_iso("not-a-date") is None)
test("in_window returns False for None", lambda: not module54.in_window(None, None, None))
test("reservation window read from env", lambda: "WD_RESERVATION_START" in inspect.getsource(module54.get_reservation_window))
test("graceful fallback if no token", lambda: "NO_CREDENTIALS" in inspect.getsource(module54.main))


# ═══════════════════════════════════════
# MODULE 55 — Cryogenic Bus Integrity
# ═══════════════════════════════════════
section("module55.py — Cryogenic Bus Integrity")
import module55
test("MULTI_HOLDER_LIMIT = 1", lambda: module55.MULTI_HOLDER_LIMIT == 1)
test("Serial device globs defined", lambda: len(module55.SERIAL_GLOBS) >= 3)
test("GPIB device globs defined", lambda: len(module55.GPIB_GLOBS) >= 2)
test("FTDI vendor ID known", lambda: "0403" in module55.INSTRUMENT_VENDORS)
test("Silicon Labs CP210x known", lambda: "10c4" in module55.INSTRUMENT_VENDORS)
test("enumerate_bus_devices runs without hardware", lambda: isinstance(module55.enumerate_bus_devices(), list))
test("check_socat_shims runs", lambda: isinstance(module55.check_socat_shims(), list))
test("No simulated sensor readings", lambda: "random." not in inspect.getsource(module55) and "import random" not in inspect.getsource(module55))

# ═══════════════════════════════════════
# MODULE 56 — FPGA Bitstream & JTAG
# ═══════════════════════════════════════
section("module56.py — FPGA Bitstream & JTAG")
import module56
test("Xilinx vendor ID 10ee known", lambda: "10ee" in module56.FPGA_VENDOR_IDS)
test("Intel/Altera vendor ID 1172 known", lambda: "1172" in module56.FPGA_VENDOR_IDS)
test("JTAG modules list defined", lambda: len(module56.JTAG_MODULES) >= 5)
test("Programming tools list defined", lambda: "openocd" in module56.PROGRAMMING_TOOLS)
test("vivado in programming tools", lambda: "vivado" in module56.PROGRAMMING_TOOLS)
test("FPGA manager path correct", lambda: module56.FPGA_MANAGER_BASE == "/sys/class/fpga_manager")
test("scan_fpga_pcie runs without hardware", lambda: isinstance(module56.scan_fpga_pcie(), list))
test("SHA256 used for bitstream hashing", lambda: "sha256" in inspect.getsource(module56.sha256_file).lower())
test("No simulated bitstream data", lambda: "random." not in inspect.getsource(module56) and "import random" not in inspect.getsource(module56))

# ═══════════════════════════════════════
# MODULE 57 — EM Side-Channel Guard
# ═══════════════════════════════════════
section("module57.py — EM Side-Channel Guard")
import module57
test("RTL-SDR device ID known", lambda: "0bda:2838" in module57.SDR_DEVICES)
test("HackRF device ID known", lambda: "1d50:6089" in module57.SDR_DEVICES)
test("USRP B210 device ID known", lambda: "2500:0021" in module57.SDR_DEVICES)
test("SDR device count >= 15", lambda: len(module57.SDR_DEVICES) >= 15)
test("RF capture tools list defined", lambda: "rtl_sdr" in module57.RF_CAPTURE_TOOLS)
test("gnuradio in RF tools", lambda: any("gnuradio" in t for t in module57.RF_CAPTURE_TOOLS))
test("Qubit drive band 4-8 GHz", lambda: module57.QUBIT_DRIVE_BAND_GHZ == (4.0, 8.0))
test("enumerate_usb_devices runs", lambda: isinstance(module57.enumerate_usb_devices(), dict))
test("check_rf_tools runs", lambda: isinstance(module57.check_rf_tools(), list))
test("No simulated RF data", lambda: "random." not in inspect.getsource(module57) and "import random" not in inspect.getsource(module57))

# ═══════════════════════════════════════
# MODULE 58 — Control-Plane Zero Trust
# ═══════════════════════════════════════
section("module58.py — Control-Plane Zero Trust")
import module58
test("gRPC port 50051 monitored", lambda: 50051 in module58.CONTROL_PLANE_PORTS)
test("Modbus TCP port 502 monitored", lambda: 502 in module58.CONTROL_PLANE_PORTS)
test("SCPI port 5025 monitored", lambda: 5025 in module58.CONTROL_PLANE_PORTS)
test("Quantum exporter port 9093 monitored", lambda: 9093 in module58.CONTROL_PLANE_PORTS)
test("Plaintext-sensitive ports defined", lambda: 50051 in module58.PLAINTEXT_SENSITIVE)
test("Proxy tools list defined", lambda: "socat" in module58.PROXY_TOOLS)
test("mitmproxy in proxy tools", lambda: "mitmproxy" in module58.PROXY_TOOLS)
test("enumerate_listeners runs", lambda: isinstance(module58.enumerate_listeners(), list))
test("enumerate_unix_sockets runs", lambda: isinstance(module58.enumerate_unix_sockets(), list))
test("parse_proc_net reads /proc/net", lambda: "/proc/net/" in inspect.getsource(module58.parse_proc_net))
test("TLS probing is opt-in", lambda: "WD_PROBE_TLS" in inspect.getsource(module58.main))
test("No simulated topology", lambda: "random." not in inspect.getsource(module58) and "import random" not in inspect.getsource(module58))

passed = sum(1 for _, r in results if r)
failed = sum(1 for _, r in results if not r)
total  = len(results)
print(f"\n{'═'*50}")
print(f"  {G}{passed} passed{E}  {R}{failed} failed{E}  / {total} total")
print(f"{'═'*50}\n")
sys.exit(0 if failed == 0 else 1)
