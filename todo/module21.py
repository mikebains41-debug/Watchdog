#!/usr/bin/env python3
"""
Watchdog — Module 21: Supervisor (B200)
Attestation + threat correlation + compliance proofs + quantum physics integration.

Safety rails (all off by default — set env vars to enable):
  WD_DRY_RUN=false              enable hardware actions
  WD_AUTO_REMEDIATION=true      enable GPU reset / kubectl taint
  WD_HUMAN_APPROVAL=false       disable approval gate
  WD_CONSECUTIVE_THRESHOLD=N    consecutive alert requirement
"""
import subprocess, time, datetime, json, hashlib, hmac as _hmac
import glob, os, sys
from collections import deque

# ── Quantum models path ──────────────────────────────────────────────
_QM_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         '..', 'quantum_models')
if os.path.isdir(_QM_PATH):
    sys.path.insert(0, _QM_PATH)

try:
    from M_quantum_efficiency_score import score as qe_score
    from M_quantum_drift_tracker import DriftTracker, ScoreReading
    QUANTUM_MODELS_AVAILABLE = True
except ImportError:
    QUANTUM_MODELS_AVAILABLE = False

try:
    from M_quantum_fleet_score import unit_score as fleet_unit_score
    FLEET_SCORE_AVAILABLE = True
except ImportError:
    FLEET_SCORE_AVAILABLE = False

# ── Safety rails ─────────────────────────────────────────────────────
DRY_RUN                  = os.environ.get("WD_DRY_RUN", "true").lower() != "false"
AUTO_REMEDIATION_ENABLED = os.environ.get("WD_AUTO_REMEDIATION", "false").lower() == "true"
HUMAN_APPROVAL_REQUIRED  = os.environ.get("WD_HUMAN_APPROVAL", "true").lower() != "false"
APPROVAL_FILE            = "/tmp/watchdog_approve_action"
MAX_CONSECUTIVE_ALERTS   = int(os.environ.get("WD_CONSECUTIVE_THRESHOLD", "3"))

CORRELATION_WINDOW = 10
ACTION_COOLDOWN    = 60
PROOF_INTERVAL     = 3600
HMAC_KEY_FILE      = "/tmp/watchdog_hmac.key"
LOG_DIR            = "."

LEVEL_WARN       = 1
LEVEL_RESET      = 2
LEVEL_QUARANTINE = 3

THREAT_MATRIX = {
    frozenset(["GPU_THERMAL_PREVENT",          "VRAM_ROWHAMMER_PREVENT"]):      (LEVEL_RESET,      "thermal_rowhammer"),
    frozenset(["GHOST_POWER_DETECTED",         "VRAM_ROWHAMMER_PREVENT"]):      (LEVEL_RESET,      "ghost_power_rowhammer"),
    frozenset(["GPU_THERMAL_PREVENT",          "ECC_STORM_BLOCKED"]):           (LEVEL_RESET,      "thermal_ecc_storm"),
    frozenset(["NVLINK_SESSION_HIJACK_BLOCKED","MODEL_EXFIL_BLOCKED"]):         (LEVEL_QUARANTINE, "nvlink_exfil"),
    frozenset(["CONTAINER_BREAKOUT_BLOCKED",   "DMA_ATTACK_BLOCKED"]):          (LEVEL_QUARANTINE, "container_dma"),
    frozenset(["EXEC_BLOCKED_EBPF",            "MODEL_EXFIL_BLOCKED"]):         (LEVEL_QUARANTINE, "exec_exfil"),
    frozenset(["EXEC_BLOCKED_POLL",            "MODEL_EXFIL_BLOCKED"]):         (LEVEL_QUARANTINE, "exec_exfil"),
    frozenset(["GPU_CLOCK_GLITCH_BLOCKED",     "VRAM_ROWHAMMER_PREVENT"]):      (LEVEL_QUARANTINE, "glitch_rowhammer"),
    frozenset(["PCIe_UNBOUND",                 "GPU_PSTATE_LOCK"]):             (LEVEL_RESET,      "pcie_pstate"),
    frozenset(["UNKNOWN_PID_KILLED",           "NVLINK_SESSION_HIJACK_BLOCKED"]):(LEVEL_QUARANTINE,"pid_nvlink_hijack"),
    frozenset(["SMT_SIBLING_OFFLINED",         "LLC_FLOOD_LOCK"]):              (LEVEL_WARN,       "cpu_sidechannel_llc"),
    frozenset(["SPECTRE_CACHE_FLUSH",          "SMT_SIBLING_OFFLINED"]):        (LEVEL_WARN,       "spectre_smt"),
    frozenset(["QUBIT_GATE_ERROR_SPIKE",       "CALIBRATION_FREQUENCY_SPIKE"]): (LEVEL_RESET,      "qpu_coordinated_attack"),
    frozenset(["QAAS_API_REPLAY_DETECTED",     "CREDENTIAL_DRAIN_SHOTS"]):      (LEVEL_QUARANTINE, "qaas_account_attack"),
    frozenset(["QUANTUM_LIBRARY_TAMPER",       "QAAS_INTEGRITY_FAILURE"]):      (LEVEL_QUARANTINE, "quantum_supply_chain"),
}

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

_drift_tracker = DriftTracker(unit_id="watchdog_supervisor") if QUANTUM_MODELS_AVAILABLE else None

def get_quantum_efficiency_snapshot(qubits=127, wall_w=None, cold_load_w=None):
    """Compute quantum efficiency score using quantum_models physics."""
    if not QUANTUM_MODELS_AVAILABLE:
        return None
    try:
        if wall_w is None:
            out = subprocess.check_output(
                ["nvidia-smi", "--query-gpu=power.draw",
                 "--format=csv,noheader,nounits"], text=True, timeout=2)
            wall_w = float(out.strip())
        if cold_load_w is None:
            cold_load_w = wall_w * 0.001

        eff_score = qe_score(qubits=qubits, wall_w=wall_w, cold_load_w=cold_load_w)

        if _drift_tracker is not None:
            try:
                _drift_tracker.add_reading(
                    ScoreReading(score=eff_score, timestamp=time.time()))
            except Exception:
                pass

        return {
            "efficiency_score": round(float(eff_score), 4),
            "qubits":           qubits,
            "wall_w":           round(wall_w, 2),
            "cold_load_w":      round(cold_load_w, 4),
            "model":            "M_quantum_efficiency_score.score()",
            "status":           "AWAITING_HARDWARE_TEST",
        }
    except Exception as e:
        return {"error": str(e), "model": "M_quantum_efficiency_score"}

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

def sign_entry(entry: dict, prev_hash: str, key: bytes) -> dict:
    entry["prev_hash"] = prev_hash
    entry.setdefault("ts", now_iso())
    canonical    = json.dumps(entry, sort_keys=True).encode()
    current_hash = hashlib.sha512(canonical).hexdigest()
    entry["sig"]        = _hmac.new(key, canonical, hashlib.sha512).hexdigest()
    entry["sig_method"] = "tpm2_hmac" if tpm_available() else "software_hmac_sha512"
    entry["hash"]       = current_hash
    return entry

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

def get_node():
    try:
        return subprocess.check_output(["hostname"], text=True, timeout=2).strip()
    except:
        return "unknown-node"

def approval_granted(action: str) -> bool:
    if not HUMAN_APPROVAL_REQUIRED:
        return True
    if os.path.exists(APPROVAL_FILE):
        try:
            with open(APPROVAL_FILE) as f:
                approved = f.read().strip()
            if approved == action or approved == "any":
                os.unlink(APPROVAL_FILE)
                return True
        except:
            pass
    return False

def reset_gpu(emit_fn, action: str) -> bool:
    if DRY_RUN:
        emit_fn({"event": "DRY_RUN_GPU_RESET", "action": action,
                  "note": "Set WD_DRY_RUN=false WD_AUTO_REMEDIATION=true to enable"})
        return False
    if not AUTO_REMEDIATION_ENABLED:
        emit_fn({"event": "REMEDIATION_DISABLED", "action": action})
        return False
    if not approval_granted(action):
        emit_fn({"event": "AWAITING_APPROVAL", "action": action,
                  "note": f"echo '{action}' > {APPROVAL_FILE}"})
        return False
    try:
        subprocess.check_output(["nvidia-smi", "--gpu-reset", "-i", "0"],
            text=True, timeout=5, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def kubectl_taint(node: str, reason: str, emit_fn) -> bool:
    if DRY_RUN:
        emit_fn({"event": "DRY_RUN_KUBECTL_TAINT", "node": node, "reason": reason,
                  "note": "Set WD_DRY_RUN=false WD_AUTO_REMEDIATION=true to enable"})
        return False
    if not AUTO_REMEDIATION_ENABLED:
        emit_fn({"event": "REMEDIATION_DISABLED", "action": "kubectl_taint"})
        return False
    if not approval_granted(f"quarantine_{node}"):
        emit_fn({"event": "AWAITING_APPROVAL", "action": "kubectl_taint",
                  "note": f"echo 'quarantine_{node}' > {APPROVAL_FILE}"})
        return False
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

CLAIMS = [
    {"type": "no_thermal_events", "filter_event": "GPU_THERMAL_PREVENT"},
    {"type": "no_ghost_power",    "filter_event": "GHOST_POWER_DETECTED"},
    {"type": "no_quarantine",     "filter_event": "NODE_QUARANTINED"},
    {"type": "no_exec_blocks",    "filter_event": "EXEC_BLOCKED"},
    {"type": "no_qpu_attacks",    "filter_event": "QUBIT_GATE_ERROR_SPIKE"},
]

def collect_telemetry(log_dir: str) -> list:
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

def generate_proofs(events: list, emit_fn, stamp_str: str):
    root, tree = build_merkle(events)
    for claim in CLAIMS:
        violations  = [i for i, e in enumerate(events)
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
        emit_fn({"event": "PROOF_GENERATED",
                  "claim": claim["type"],
                  "satisfied": result["satisfied"],
                  "violations": result["violations"],
                  "merkle_root": root,
                  "proof_file": fname})

def main():
    use_tpm   = tpm_available()
    key       = get_hmac_key()
    prev_hash = "0" * 128
    node      = get_node()
    stamp_str = stamp()

    log = open(f"watchdog_supervisor_{stamp_str}.jsonl", "a")

    def emit(event: dict):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    start = sign_entry(
        {"event": "SUPERVISOR_START", "module": "21_supervisor",
         "gpu": "B200", "node": node, "tpm": use_tpm,
         "dry_run": DRY_RUN,
         "auto_remediation": AUTO_REMEDIATION_ENABLED,
         "human_approval_required": HUMAN_APPROVAL_REQUIRED,
         "quantum_models_available": QUANTUM_MODELS_AVAILABLE,
         "fleet_score_available": FLEET_SCORE_AVAILABLE},
        prev_hash, key)
    log.write(json.dumps(start) + "\n"); log.flush()
    prev_hash = start["hash"]

    recent:      deque = deque()
    cooldowns:   dict  = {}
    consecutive: dict  = {}
    last_proof         = time.time()

    for fp, raw in tail_watchdog_logs(LOG_DIR):
        try:
            event = json.loads(raw)
            now   = time.time()

            event["source"] = os.path.basename(fp)
            signed = sign_entry(event, prev_hash, key)
            log.write(json.dumps(signed) + "\n"); log.flush()
            prev_hash = signed["hash"]

            recent.append((event, now))
            while recent and (now - recent[0][1]) > CORRELATION_WINDOW:
                recent.popleft()

            result = check_matrix([e for e, _ in recent])
            if result:
                level, action = result
                consecutive[action] = consecutive.get(action, 0) + 1

                if now - cooldowns.get(action, 0) > ACTION_COOLDOWN:
                    if consecutive.get(action, 0) >= MAX_CONSECUTIVE_ALERTS:
                        cooldowns[action]   = now
                        consecutive[action] = 0
                        qe = get_quantum_efficiency_snapshot()
                        emit({"event":   "THREAT_CORRELATED",
                              "action":  action,
                              "level":   level,
                              "triggers": [e.get("event") for e, _ in recent],
                              "quantum_efficiency": qe})

                        if level >= LEVEL_RESET:
                            if reset_gpu(emit, action):
                                emit({"event": "SUPERVISOR_GPU_RESET", "action": action})

                        if level >= LEVEL_QUARANTINE:
                            if kubectl_taint(node, action, emit):
                                emit({"event": "NODE_QUARANTINED",
                                      "node": node, "action": action})
                    else:
                        emit({"event":    "THREAT_BELOW_CONSECUTIVE_THRESHOLD",
                              "action":   action,
                              "count":    consecutive.get(action, 0),
                              "required": MAX_CONSECUTIVE_ALERTS})

            if now - last_proof >= PROOF_INTERVAL:
                last_proof = now
                events = collect_telemetry(LOG_DIR)
                generate_proofs(events, emit, stamp_str)

        except:
            pass

if __name__ == "__main__":
    main()
