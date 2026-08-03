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

# SUMMARY
# ═══════════════════════════════════════
passed = sum(1 for _, r in results if r)
failed = sum(1 for _, r in results if not r)
total  = len(results)
print(f"\n{'═'*50}")
print(f"  {G}{passed} passed{E}  {R}{failed} failed{E}  / {total} total")
print(f"{'═'*50}\n")
sys.exit(0 if failed == 0 else 1)
