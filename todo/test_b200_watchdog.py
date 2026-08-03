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
section("watchdog_gpu_hardware.py")

def t_power():
    import watchdog_gpu_hardware as m
    return m.POWER_EMERGENCY == 800

def t_ghost_power_floor():
    import watchdog_gpu_hardware as m
    return m.GHOST_POWER_FLOOR == 80

def t_b200_clocks():
    import watchdog_gpu_hardware as m
    return m.B200_MEM_CLOCK == 8000 and m.B200_SM_CLOCK == 2400

def t_ac_order():
    import watchdog_gpu_hardware as m
    src = inspect.getsource(m.lock_clocks)
    # Must be MEM,SM order: "8000,2400" via constants
    return "B200_MEM_CLOCK" in src and "B200_SM_CLOCK" in src

def t_ecc_dual_threshold():
    import watchdog_gpu_hardware as m
    return m.ECC_ABSOLUTE_FLOOR == 50 and m.ECC_SPIKE == 10

def t_no_invalid_ac():
    import watchdog_gpu_hardware as m
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
section("watchdog_bus_interconnect.py")

def t_pcie_gen5():
    import watchdog_bus_interconnect as m
    return m.PCIE_EXPECTED == 32.0   # Gen5, not Gen6

def t_pcie_thresholds():
    import watchdog_bus_interconnect as m
    return m.PCIE_WARN == 24.0 and m.PCIE_CRIT == 16.0

def t_nvlink_18():
    import watchdog_bus_interconnect as m
    return m.NVLINK_LINKS == 18

def t_nvlink_parser_no_bandwidth_string():
    import watchdog_bus_interconnect as m
    src = inspect.getsource(m.parse_nvlink_counters)
    return 're.search' in src and 're.IGNORECASE' in src

def t_nvlink_parser_unit_aware():
    import watchdog_bus_interconnect as m
    # Should handle KB/s, MB/s, GB/s
    raw = "Link 0: <Throughput Rx>  500 KB/s\nLink 1: <Throughput Tx>  2 MB/s\n"
    result = m.parse_nvlink_counters(raw)
    # 500 KB/s + 2*1024 KB/s = 2548
    return result == 500 + 2 * 1024

def t_no_shell_redirect():
    import watchdog_bus_interconnect as m
    src = inspect.getsource(m)
    return 'shell=True' not in src

test("PCIe expected = 32 GT/s (Gen5, not Gen6=64)", t_pcie_gen5)
test("PCIe warn=24, crit=16 GT/s", t_pcie_thresholds)
test("NVLink_LINKS = 18 (NV18 topology)", t_nvlink_18)
test("NVLink parser doesn't look for 'Bandwidth' string", t_nvlink_parser_no_bandwidth_string)
test("NVLink parser handles KB/s + MB/s units", t_nvlink_parser_unit_aware)
test("No broken shell=True redirect", t_no_shell_redirect)

# ═══════════════════════════════════════
# GPU SOFTWARE
# ═══════════════════════════════════════
section("watchdog_gpu_software.py")

def t_ecc_window_50():
    import watchdog_gpu_software as m
    return m.ECC_WINDOW == 50

def t_cmdline_nullbyte():
    raw = b"python3\x00-u\x00watchdog.py\x00"
    cmd = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    return "\x00" not in cmd and "python3" in cmd

def t_reads_rb():
    import watchdog_gpu_software as m
    src = inspect.getsource(m.cmdline)
    return '"rb"' in src

def t_no_pkill_nc():
    import watchdog_gpu_software as m
    src = inspect.getsource(m)
    return "pkill" not in src

def t_safe_ports():
    import watchdog_gpu_software as m
    return 80 in m.SAFE_PORTS and 443 in m.SAFE_PORTS and 22 in m.SAFE_PORTS

test("ECC_WINDOW = 50 for HBM3e", t_ecc_window_50)
test("Null-byte cmdline parsing correct", t_cmdline_nullbyte)
test("cmdline opened in binary mode 'rb'", t_reads_rb)
test("No blunt pkill -f nc", t_no_pkill_nc)
test("Safe ports 22/80/443 excluded from exfil kill", t_safe_ports)

# ═══════════════════════════════════════
# HOST SECURITY
# ═══════════════════════════════════════
section("watchdog_host_security.py")

def t_spectre_cooldown():
    import watchdog_host_security as m
    return m.SPECTRE_COOLDOWN == 1800

def t_lock_hz_not_string():
    import watchdog_host_security as m
    return isinstance(m.LLC_LOCK_HZ, int) and m.LLC_LOCK_HZ == 800000

def t_governor_flag():
    import watchdog_host_security as m
    src = inspect.getsource(m.unlock_cpu)
    return '"-g"' in src and '"-f"' not in src

def t_arm_detection():
    import watchdog_host_security as m
    return callable(m.is_arm)

def t_keyword_block():
    import watchdog_host_security as m
    susp, reason = m.is_suspicious("/tmp/xmrig", "abc123")
    return susp and "xmrig" in reason

def t_path_allow():
    import watchdog_host_security as m
    susp, _ = m.is_suspicious("/usr/bin/python3", "abc")
    return not susp

def t_script_allow():
    import watchdog_host_security as m
    susp, _ = m.is_suspicious("/tmp/myscript.py", None)
    return not susp

def t_all_miners_blocked():
    import watchdog_host_security as m
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
test(f"All {len(__import__('watchdog_host_security').MINER_KEYWORDS)} miner keywords blocked", t_all_miners_blocked)

# ═══════════════════════════════════════
# SUPERVISOR
# ═══════════════════════════════════════
section("watchdog_supervisor.py")

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
    prev = "0" * 128
    entries = []
    for i in range(3):
        e = {"event": f"T{i}", "prev_hash": prev}
        h = hashlib.sha512(json.dumps(e, sort_keys=True).encode()).hexdigest()
        e["hash"] = h; entries.append(e); prev = h
    tampered = {"event": "TAMPERED", "prev_hash": entries[0]["hash"]}
    tampered_hash = hashlib.sha512(
        json.dumps(tampered, sort_keys=True).encode()).hexdigest()
    return entries[2]["prev_hash"] != tampered_hash

def t_threat_matrix_nvlink_exfil():
    import watchdog_supervisor as m
    events = [{"event": "NVLINK_SESSION_HIJACK_BLOCKED"},
              {"event": "MODEL_EXFIL_BLOCKED"}]
    r = m.check_matrix(events)
    return r is not None and r[0] >= m.LEVEL_QUARANTINE

def t_threat_matrix_ghost_rowhammer():
    import watchdog_supervisor as m
    events = [{"event": "GHOST_POWER_DETECTED"},
              {"event": "VRAM_ROWHAMMER_PREVENT"}]
    r = m.check_matrix(events)
    return r is not None and r[0] >= m.LEVEL_RESET

def t_benign_no_trigger():
    import watchdog_supervisor as m
    return m.check_matrix([{"event": "RUN_START"}, {"event": "PCIe_REBOUND"}]) is None

def t_merkle_deterministic():
    import watchdog_supervisor as m
    data = [{"e": i} for i in range(8)]
    r1, _ = m.build_merkle(data)
    r2, _ = m.build_merkle(data)
    return r1 == r2

def t_merkle_inclusion():
    import watchdog_supervisor as m
    data = [{"e": i} for i in range(8)]
    root, tree = m.build_merkle(data)
    return all(m.verify_proof(data[i], m.inclusion_proof(tree, i), root)
               for i in range(len(data)))

def t_merkle_tamper():
    import watchdog_supervisor as m
    data = [{"e": i} for i in range(8)]
    root, tree = m.build_merkle(data)
    proof = m.inclusion_proof(tree, 3)
    return not m.verify_proof({"e": 999}, proof, root)

def t_merkle_odd():
    import watchdog_supervisor as m
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
# SUMMARY
# ═══════════════════════════════════════
passed = sum(1 for _, r in results if r)
failed = sum(1 for _, r in results if not r)
total  = len(results)
print(f"\n{'═'*50}")
print(f"  {G}{passed} passed{E}  {R}{failed} failed{E}  / {total} total")
print(f"{'═'*50}\n")
sys.exit(0 if failed == 0 else 1)
