#!/usr/bin/env python3
"""
Watchdog — Supervisor (B200)
Combines: hardware attestation (was 27) + remediation (was 28) + compliance (was 29)

Runs alongside the 4 hardware modules. Tails their JSONL logs and:
  1. Signs every event into a tamper-evident hash chain (TPM if available)
  2. Correlates events in 10s window → autonomous remediation decisions
  3. Every hour: generates Merkle commitment proofs for compliance (EU AI Act)
"""
import subprocess, time, datetime, json, hashlib, hmac as _hmac
import glob, os
from collections import deque

# ── Constants ───────────────────────────────────────────────────────
CORRELATION_WINDOW  = 10      # seconds
ACTION_COOLDOWN     = 60      # seconds per action before re-trigger
PROOF_INTERVAL      = 3600    # seconds between compliance proofs
HMAC_KEY_FILE       = "/tmp/watchdog_hmac.key"
LOG_DIR             = "."

LEVEL_WARN          = 1
LEVEL_RESET         = 2
LEVEL_QUARANTINE    = 3

# Threat matrix: frozenset of co-occurring events → (level, action_name)
THREAT_MATRIX = {
    frozenset(["GPU_THERMAL_PREVENT",          "VRAM_ROWHAMMER_PREVENT"]):     (LEVEL_RESET,       "thermal_rowhammer"),
    frozenset(["GHOST_POWER_DETECTED",         "VRAM_ROWHAMMER_PREVENT"]):     (LEVEL_RESET,       "ghost_power_rowhammer"),
    frozenset(["GPU_THERMAL_PREVENT",          "ECC_STORM_BLOCKED"]):          (LEVEL_RESET,       "thermal_ecc_storm"),
    frozenset(["NVLINK_SESSION_HIJACK_BLOCKED","MODEL_EXFIL_BLOCKED"]):        (LEVEL_QUARANTINE,  "nvlink_exfil"),
    frozenset(["CONTAINER_BREAKOUT_BLOCKED",   "DMA_ATTACK_BLOCKED"]):         (LEVEL_QUARANTINE,  "container_dma"),
    frozenset(["EXEC_BLOCKED_EBPF",            "MODEL_EXFIL_BLOCKED"]):        (LEVEL_QUARANTINE,  "exec_exfil"),
    frozenset(["EXEC_BLOCKED_POLL",            "MODEL_EXFIL_BLOCKED"]):        (LEVEL_QUARANTINE,  "exec_exfil"),
    frozenset(["GPU_CLOCK_GLITCH_BLOCKED",     "VRAM_ROWHAMMER_PREVENT"]):     (LEVEL_QUARANTINE,  "glitch_rowhammer"),
    frozenset(["PCIe_UNBOUND",                 "GPU_PSTATE_LOCK"]):            (LEVEL_RESET,       "pcie_pstate"),
    frozenset(["UNKNOWN_PID_KILLED",           "NVLINK_SESSION_HIJACK_BLOCKED"]):(LEVEL_QUARANTINE, "pid_nvlink_hijack"),
    frozenset(["SMT_SIBLING_OFFLINED",         "LLC_FLOOD_LOCK"]):             (LEVEL_WARN,        "cpu_sidechannel_llc"),
    frozenset(["SPECTRE_CACHE_FLUSH",          "SMT_SIBLING_OFFLINED"]):       (LEVEL_WARN,        "spectre_smt"),
}

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ── Attestation helpers ─────────────────────────────────────────────
def tpm_available():
    return os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0")

def get_hmac_key() -> bytes:
    if not os.path.exists(HMAC_KEY_FILE):
        key = os.urandom(64)
        with open(HMAC_KEY_FILE, "wb") as f:
            f.write(key)
        os.chmod(HMAC_KEY_FILE, 0o600)
    with open(HMAC_KEY_FILE, "rb") as f:
        return f.read()

def tpm_sign(data: bytes):
    try:
        tmp = "/tmp/wd_tpm_input.bin"
        with open(tmp, "wb") as f:
            f.write(data)
        subprocess.check_output(
            ["tpm2_createprimary", "-c", "/tmp/wd_primary.ctx", "-G", "rsa"],
            timeout=5, stderr=subprocess.DEVNULL)
        subprocess.check_output(
            ["tpm2_create", "-C", "/tmp/wd_primary.ctx", "-G", "hmac",
             "-u", "/tmp/wd_hmac.pub", "-r", "/tmp/wd_hmac.priv"],
            timeout=5, stderr=subprocess.DEVNULL)
        subprocess.check_output(
            ["tpm2_load", "-C", "/tmp/wd_primary.ctx",
             "-u", "/tmp/wd_hmac.pub", "-r", "/tmp/wd_hmac.priv",
             "-c", "/tmp/wd_hmac.ctx"],
            timeout=5, stderr=subprocess.DEVNULL)
        out = subprocess.check_output(
            ["tpm2_hmac", "-c", "/tmp/wd_hmac.ctx", tmp],
            timeout=5, stderr=subprocess.DEVNULL)
        return out.hex()
    except:
        return None

def sign_entry(entry: dict, prev_hash: str, key: bytes, use_tpm: bool) -> dict:
    entry["prev_hash"] = prev_hash
    entry.setdefault("ts", now_iso())
    canonical    = json.dumps(entry, sort_keys=True).encode()
    current_hash = hashlib.sha512(canonical).hexdigest()

    if use_tpm:
        sig = tpm_sign(canonical)
        if sig is None:
            sig = _hmac.new(key, canonical, hashlib.sha512).hexdigest()
            entry["sig_method"] = "software_hmac_sha512_tpm_fallback"
        else:
            entry["sig_method"] = "tpm2_hmac"
    else:
        sig = _hmac.new(key, canonical, hashlib.sha512).hexdigest()
        entry["sig_method"] = "software_hmac_sha512"

    entry["sig"]  = sig
    entry["hash"] = current_hash
    return entry

# ── Merkle compliance helpers ───────────────────────────────────────
def h3(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()

def build_merkle(leaves: list) -> tuple:
    if not leaves:
        return h3(b"empty"), []
    level = [h3(json.dumps(l, sort_keys=True).encode()) for l in leaves]
    tree  = [level[:]]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [h3((level[i] + level[i+1]).encode())
                 for i in range(0, len(level), 2)]
        tree.append(level[:])
    return level[0], tree

def inclusion_proof(tree: list, index: int) -> list:
    proof = []
    for level in tree[:-1]:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        pos = "right" if index % 2 == 0 else "left"
        sib = index + 1 if index % 2 == 0 else index - 1
        proof.append({"sibling": level[sib], "position": pos})
        index //= 2
    return proof

def verify_proof(leaf: dict, proof: list, root: str) -> bool:
    cur = h3(json.dumps(leaf, sort_keys=True).encode())
    for step in proof:
        sib = step["sibling"]
        cur = h3((cur + sib).encode() if step["position"] == "right"
                 else (sib + cur).encode())
    return cur == root

# ── Log tailing ─────────────────────────────────────────────────────
def tail_watchdog_logs(log_dir: str):
    positions = {}
    while True:
        for fp in sorted(glob.glob(os.path.join(log_dir, "watchdog_*.jsonl"))):
            if "supervisor" in fp:
                continue
            pos = positions.get(fp, 0)
            try:
                with open(fp, "r") as f:
                    f.seek(pos)
                    for line in f:
                        line = line.strip()
                        if line:
                            yield fp, line
                    positions[fp] = f.tell()
            except:
                pass
        time.sleep(0.5)

# ── Remediation ─────────────────────────────────────────────────────
def get_node():
    try:
        return subprocess.check_output(
            ["hostname"], text=True, timeout=2).strip()
    except:
        return "unknown-node"

def reset_gpu():
    try:
        subprocess.check_output(
            ["nvidia-smi", "--gpu-reset", "-i", "0"],
            text=True, timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def kubectl_taint(node: str, reason: str) -> bool:
    try:
        subprocess.check_output([
            "kubectl", "taint", "nodes", node,
            f"watchdog.quarantine={reason}:NoSchedule", "--overwrite"
        ], timeout=10, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def check_matrix(events: list):
    types = frozenset(e.get("event", "") for e in events)
    best_level, best_action = 0, None
    for threat, (level, action) in THREAT_MATRIX.items():
        if threat.issubset(types) and level > best_level:
            best_level, best_action = level, action
    return (best_level, best_action) if best_level > 0 else None

# ── Compliance ──────────────────────────────────────────────────────
CLAIMS = [
    {"type": "no_thermal_events",  "filter_event": "GPU_THERMAL_PREVENT"},
    {"type": "no_ghost_power",     "filter_event": "GHOST_POWER_DETECTED"},
    {"type": "no_quarantine",      "filter_event": "NODE_QUARANTINED"},
    {"type": "no_exec_blocks",     "filter_event": "EXEC_BLOCKED"},
]

def collect_all_telemetry(log_dir: str) -> list:
    events = []
    for fp in sorted(glob.glob(os.path.join(log_dir, "watchdog_*.jsonl"))):
        if "supervisor" in fp:
            continue
        try:
            with open(fp, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except:
                            pass
        except:
            pass
    return events

def generate_proofs(events: list, log_emit, stamp_str: str):
    root, tree = build_merkle(events)
    for claim in CLAIMS:
        violations = [i for i, e in enumerate(events)
                      if claim["filter_event"] in e.get("event", "")]
        proof_paths = []
        for idx in violations[:20]:
            proof_paths.append({
                "index":     idx,
                "leaf_hash": h3(json.dumps(events[idx], sort_keys=True).encode()),
                "proof":     inclusion_proof(tree, idx)
            })
        result = {
            "version":      "1.0",
            "claim":        claim["type"],
            "satisfied":    len(violations) == 0,
            "violations":   len(violations),
            "merkle_root":  root,
            "total_events": len(events),
            "proof_paths":  proof_paths,
            "hash_fn":      "SHA3-256",
            "regulation":   "EU AI Act / NIST AI RMF",
            "generated_at": now_iso(),
        }
        fname = f"compliance_{claim['type']}_{stamp_str}.json"
        with open(fname, "w") as pf:
            json.dump(result, pf, indent=2)
        log_emit({"event": "PROOF_GENERATED",
                  "claim": claim["type"],
                  "satisfied": result["satisfied"],
                  "violations": result["violations"],
                  "merkle_root": root,
                  "proof_file": fname})

# ── main ────────────────────────────────────────────────────────────
def main():
    use_tpm    = tpm_available()
    key        = get_hmac_key()
    prev_hash  = "0" * 128
    node       = get_node()
    stamp_str  = stamp()

    log = open(f"watchdog_supervisor_{stamp_str}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    # Sign start entry
    start = sign_entry(
        {"event": "SUPERVISOR_START", "module": "supervisor",
         "gpu": "B200", "node": node, "tpm": use_tpm},
        prev_hash, key, use_tpm)
    log.write(json.dumps(start) + "\n"); log.flush()
    prev_hash = start["hash"]

    recent:    deque = deque()     # (event_dict, time.time())
    cooldowns: dict  = {}          # action → last_trigger
    last_proof       = time.time()

    for fp, raw in tail_watchdog_logs(LOG_DIR):
        try:
            event = json.loads(raw)
            now   = time.time()

            # ── Attestation: sign and chain every event ──
            event["source"] = os.path.basename(fp)
            signed = sign_entry(event, prev_hash, key, use_tpm)
            log.write(json.dumps(signed) + "\n"); log.flush()
            prev_hash = signed["hash"]

            # ── Threat correlation ──
            recent.append((event, now))
            while recent and (now - recent[0][1]) > CORRELATION_WINDOW:
                recent.popleft()

            result = check_matrix([e for e, _ in recent])
            if result:
                level, action = result
                if now - cooldowns.get(action, 0) > ACTION_COOLDOWN:
                    cooldowns[action] = now
                    emit({"event": "THREAT_CORRELATED",
                          "action": action, "level": level,
                          "triggers": [e.get("event")
                                       for e, _ in recent]})
                    if level >= LEVEL_RESET:
                        if reset_gpu():
                            emit({"event": "SUPERVISOR_GPU_RESET",
                                  "action": action})
                    if level >= LEVEL_QUARANTINE:
                        if kubectl_taint(node, action):
                            emit({"event": "NODE_QUARANTINED",
                                  "node": node, "action": action})

            # ── Compliance proofs (every hour) ──
            if now - last_proof >= PROOF_INTERVAL:
                last_proof = now
                events = collect_all_telemetry(LOG_DIR)
                generate_proofs(events, emit, stamp_str)

        except:
            pass

if __name__ == "__main__":
    main()
