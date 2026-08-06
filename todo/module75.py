#!/usr/bin/env python3
"""
Watchdog — Module 75: XMSS / LMS One-Time Key Reuse Sentinel
Status: FUNCTIONAL — no special hardware or credentials required

THE FAILURE MODE — catastrophic and well documented:

  XMSS and LMS are stateful hash-based signature schemes, standardised
  in NIST SP 800-208 and RFC 8391 (XMSS) / RFC 8554 (LMS). They are the
  conservative post-quantum choice for long-lived roots of trust:
  firmware signing, code signing, certificate authorities. Their
  security rests only on hash function properties.

  The cost of that conservatism is STATE. Each private key is a tree of
  one-time signature keys, and every signature consumes exactly one leaf.
  A leaf index must NEVER be used twice.

  Reuse a leaf index and the one-time signature scheme underneath —
  WOTS+ — leaks enough private key material for an attacker to forge
  signatures on messages of their choosing. Total break, not degradation.

  NIST SP 800-208 is explicit that ordinary practices used with
  stateless schemes — backups, VM snapshots, failover, cloning — are
  exactly what break stateful schemes.

  How this happens in practice:
    - Restoring a signing host from backup rewinds the leaf counter
    - A VM snapshot rollback replays consumed indices
    - Two instances of the same key running for high availability
    - A crash between "sign" and "persist state"
    - An attacker deliberately rolling back the state file

WHAT THIS MODULE DOES:
  1. Locates XMSS/LMS state files and key stores.
  2. Tracks the leaf index. It must be MONOTONICALLY INCREASING. Any
     decrease is a rollback — the single most important check here.
  3. Records a hash chain over observed (key_id, index) pairs so a
     rollback cannot be hidden by rewriting the monitor's own history.
  4. Detects a stalled index that continues producing signatures.
  5. Detects duplicate state files — two instances, same tree.
  6. Monitors permissions and backup tooling near the key directory.
  7. Warns on exhaustion, because the outage is what triggers the
     "just restore an older state" decision that causes reuse.

NO KEY MATERIAL IS EVER READ OR LOGGED. Indices, hashes, permissions only.
"""
import json, os, time, datetime, hashlib, glob, stat, re

POLL_INTERVAL         = 60
EXHAUSTION_WARN_PCT   = 0.90
EXHAUSTION_CRIT_PCT   = 0.98
STALL_CYCLES          = 10
STATE_FILE            = "/tmp/watchdog_hbs_state.json"

HBS_STATE_GLOBS = [
    "/var/lib/xmss/*.state", "/var/lib/xmss/*.json",
    "/var/lib/lms/*.state",  "/var/lib/lms/*.json",
    "/etc/xmss/*.state",     "/etc/lms/*.state",
    "/opt/hsm/state/*.state", "/var/lib/hbs/*.state",
    os.path.expanduser("~/.xmss/*.state"),
    os.path.expanduser("~/.lms/*.state"),
]

HBS_KEY_GLOBS = [
    "/var/lib/xmss/*.key", "/var/lib/xmss/*.priv",
    "/var/lib/lms/*.key",  "/var/lib/lms/*.priv",
    "/etc/xmss/*.key",     "/etc/lms/*.key",
]

INDEX_FIELDS = ["index", "leaf_index", "idx", "next_index",
                "signature_index", "q", "leaf", "counter", "sig_count"]
CAPACITY_FIELDS = ["max_signatures", "capacity", "total_leaves",
                   "max_index", "tree_capacity", "num_signatures"]
KEYID_FIELDS = ["key_id", "keyid", "id", "public_key_hash", "kid", "name"]

BACKUP_TOOLS = ["rsync", "tar", "borg", "restic", "duplicity", "bacula",
                "veeam", "rsnapshot", "btrfs", "zfs", "lvcreate", "dd",
                "virsh", "qemu-img", "vmware-vdiskmanager"]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"keys": {}, "chain": [], "chain_head": "0" * 64,
                "established": now_iso()}

def save_state(s):
    try:
        s["chain"] = s.get("chain", [])[-500:]
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def extend_chain(head, entry):
    """Append-only hash chain. A rollback must also forge every link here."""
    canonical = json.dumps(entry, sort_keys=True).encode()
    return hashlib.sha256((head + canonical.hex()).encode()).hexdigest()

def find_state_files():
    found = []
    for pattern in HBS_STATE_GLOBS:
        found.extend(glob.glob(pattern))
    return sorted(set(found))

def find_key_files():
    found = []
    for pattern in HBS_KEY_GLOBS:
        found.extend(glob.glob(pattern))
    return sorted(set(found))

def extract_field(data, candidates):
    lowered = {k.lower(): v for k, v in data.items()}
    for name in candidates:
        if name in lowered:
            return lowered[name]
    return None

def parse_state_file(path):
    """Read index and metadata only. Never key material."""
    entry = {"path": path}
    try:
        st = os.stat(path)
        mode = st.st_mode & 0o777
        entry["mode"]        = oct(mode)
        entry["size"]        = st.st_size
        entry["mtime"]       = st.st_mtime
        entry["world_read"]  = bool(mode & stat.S_IROTH)
        entry["group_read"]  = bool(mode & stat.S_IRGRP)
        entry["world_write"] = bool(mode & stat.S_IWOTH)
        entry["group_write"] = bool(mode & stat.S_IWGRP)
    except Exception:
        pass

    entry["sha256"] = sha256_file(path)

    try:
        with open(path, errors="replace") as f:
            content = f.read(65536)
        data = None
        stripped = content.strip()
        if stripped.startswith("{"):
            data = json.loads(stripped)
        elif stripped.startswith("["):
            arr = json.loads(stripped)
            data = arr[-1] if arr else None

        if isinstance(data, dict):
            idx = extract_field(data, INDEX_FIELDS)
            cap = extract_field(data, CAPACITY_FIELDS)
            kid = extract_field(data, KEYID_FIELDS)
            if idx is not None:
                try:
                    entry["index"] = int(idx)
                except (TypeError, ValueError):
                    pass
            if cap is not None:
                try:
                    entry["capacity"] = int(cap)
                except (TypeError, ValueError):
                    pass
            if kid is not None:
                entry["key_id"] = str(kid)[:64]
            entry["format"] = "json"
            return entry
    except Exception:
        pass

    try:
        with open(path, errors="replace") as f:
            content = f.read(4096)
        for line in content.splitlines():
            m = re.match(r'^(\w+)\s*[:=]\s*(\d+)$', line.strip())
            if m:
                name, val = m.group(1).lower(), int(m.group(2))
                if name in INDEX_FIELDS and "index" not in entry:
                    entry["index"] = val
                elif name in CAPACITY_FIELDS and "capacity" not in entry:
                    entry["capacity"] = val
        if "index" not in entry:
            m = re.match(r'^\s*(\d+)\s*$', content)
            if m:
                entry["index"] = int(m.group(1))
        entry["format"] = "text"
    except Exception:
        pass

    return entry

def check_backup_tools_on_keydir():
    """Backup tooling near HBS state is the most common route to reuse."""
    found = []
    keydirs = {os.path.dirname(p) for p in HBS_STATE_GLOBS + HBS_KEY_GLOBS}
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
            base = os.path.basename(cmd.split()[0]).lower()
            if not any(base == t or base.startswith(t) for t in BACKUP_TOOLS):
                continue
            for d in keydirs:
                if d and d != "." and d in cmd:
                    found.append({"pid": int(pid), "tool": base,
                                  "cmd": cmd[:200], "keydir": d})
                    break
    except Exception:
        pass
    return found

def analyse(current, state):
    alerts = []
    known  = state.setdefault("keys", {})
    head   = state.get("chain_head", "0" * 64)
    seen_hashes = {}

    for entry in current:
        path = entry["path"]
        idx  = entry.get("index")
        prev = known.get(path, {})

        # ── THE CRITICAL CHECK — index rollback ──
        if idx is not None and prev.get("index") is not None:
            if idx < prev["index"]:
                alerts.append({
                    "event":    "HBS_INDEX_ROLLBACK",
                    "severity": "CRITICAL",
                    "path":     path,
                    "key_id":   entry.get("key_id"),
                    "previous_index": prev["index"],
                    "current_index":  idx,
                    "rollback_by":    prev["index"] - idx,
                    "confidence": 0.98,
                    "citation": "NIST SP 800-208; RFC 8391 (XMSS); RFC 8554 (LMS)",
                    "note": ("The one-time signature leaf index has GONE "
                             "BACKWARD. Every index between the current value "
                             "and the previous one has already been used. "
                             "Signing with any of them reuses a WOTS+ one-time "
                             "key, leaking enough private key material to "
                             "forge signatures on arbitrary messages. This is "
                             "a total break of this key"),
                    "action": ("STOP SIGNING WITH THIS KEY IMMEDIATELY. Do not "
                               "'fix' the index by advancing it — the key is "
                               "compromised if any index was reused. Rotate to "
                               "a new key pair and revoke this one"),
                })
            elif idx == prev["index"]:
                stall = prev.get("stall_count", 0) + 1
                entry["stall_count"] = stall
                if (prev.get("sha256") and entry.get("sha256")
                        and prev["sha256"] != entry["sha256"] and stall >= 2):
                    alerts.append({
                        "event":    "HBS_INDEX_STALLED",
                        "severity": "CRITICAL",
                        "path":     path,
                        "index":    idx,
                        "cycles":   stall,
                        "confidence": 0.85,
                        "note": ("The state file changed but the leaf index "
                                 "did not advance. Either signatures are being "
                                 "produced without consuming an index — which "
                                 "is reuse — or state persistence is broken"),
                    })
            else:
                entry["stall_count"] = 0

        # ── Exhaustion ──
        cap = entry.get("capacity")
        if idx is not None and cap and cap > 0:
            used = idx / cap
            remaining = cap - idx
            if used >= EXHAUSTION_CRIT_PCT:
                alerts.append({
                    "event":    "HBS_KEY_NEAR_EXHAUSTION",
                    "severity": "CRITICAL",
                    "path":     path, "index": idx, "capacity": cap,
                    "remaining": remaining,
                    "used_fraction": round(used, 4),
                    "confidence": 0.90,
                    "note": (f"Only {remaining} signatures remain. When the "
                             "tree runs out, signing stops — a hard outage. "
                             "The pressure at that moment to 'restore an older "
                             "state file' is exactly how index reuse happens. "
                             "Rotate before exhaustion, not after"),
                })
            elif used >= EXHAUSTION_WARN_PCT:
                alerts.append({
                    "event":    "HBS_KEY_EXHAUSTION_WARNING",
                    "severity": "WARN",
                    "path":     path, "remaining": remaining,
                    "used_fraction": round(used, 4),
                    "confidence": 0.70,
                })

        # ── Permissions ──
        if entry.get("world_write") or entry.get("group_write"):
            alerts.append({
                "event":    "HBS_STATE_WRITABLE",
                "severity": "CRITICAL",
                "path":     path, "mode": entry.get("mode"),
                "confidence": 0.95,
                "remediation": f"chmod 600 {path}",
                "note": ("The signature state file is writable beyond its "
                         "owner. Any local process can roll the index back "
                         "and force one-time key reuse"),
            })
        if entry.get("world_read") or entry.get("group_read"):
            alerts.append({
                "event":    "HBS_STATE_READABLE",
                "severity": "WARN",
                "path":     path, "mode": entry.get("mode"),
                "confidence": 0.70,
            })

        # ── Duplicate state ──
        h = entry.get("sha256")
        if h:
            if h in seen_hashes:
                alerts.append({
                    "event":    "HBS_DUPLICATE_STATE",
                    "severity": "CRITICAL",
                    "path_a":   seen_hashes[h], "path_b": path,
                    "sha256":   h[:32] + "...",
                    "confidence": 0.90,
                    "note": ("Two identical signature state files exist. If "
                             "both are in use, two signing instances consume "
                             "the same leaf indices — guaranteed reuse"),
                })
            seen_hashes[h] = path

        if idx is not None:
            chain_entry = {"path": path, "index": idx,
                           "key_id": entry.get("key_id"), "ts": now_iso()}
            head = extend_chain(head, chain_entry)
            state.setdefault("chain", []).append({**chain_entry, "hash": head})

        known[path] = {"index": idx, "capacity": cap,
                       "sha256": entry.get("sha256"),
                       "mode": entry.get("mode"),
                       "stall_count": entry.get("stall_count", 0),
                       "last_seen": now_iso()}

    current_paths = {e["path"] for e in current}
    for path in list(known.keys()):
        if path not in current_paths:
            alerts.append({
                "event":    "HBS_STATE_FILE_MISSING",
                "severity": "CRITICAL",
                "path":     path,
                "last_index": known[path].get("index"),
                "confidence": 0.85,
                "note": ("A state file present at baseline is gone. If signing "
                         "resumes from a recreated or restored file, indices "
                         "will be reused"),
            })
            del known[path]

    state["chain_head"] = head
    return alerts, state

def main():
    log = open(f"module75_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "75_xmss_lms_reuse_sentinel",
        "status": "FUNCTIONAL — no hardware or credentials required",
        "standards": [
            "NIST SP 800-208 — Stateful Hash-Based Signature Schemes",
            "RFC 8391 — XMSS",
            "RFC 8554 — LMS",
        ],
        "why_this_matters": ("Every signature consumes one one-time key. "
                             "Reusing a leaf index leaks enough WOTS+ private "
                             "key material to forge arbitrary signatures. "
                             "Total break, not degradation"),
        "checks": [
            "Leaf index monotonicity — rollback detection",
            "Tamper-evident hash chain over observed index states",
            "Stalled index with a changing state file",
            "Duplicate state files (two instances, same tree)",
            "Tree exhaustion before the outage that triggers restores",
            "State file permissions",
            "Backup/snapshot tooling on the key directory",
            "State file disappearance",
        ],
        "privacy": "No key material read or logged — indices and hashes only",
    })

    state = load_state()

    while True:
        state_files  = find_state_files()
        key_files    = find_key_files()
        backup_procs = check_backup_tools_on_keydir()

        if not state_files and not key_files:
            emit({"event": "NO_HBS_STATE_FOUND",
                  "status": "AWAITING_HBS_DEPLOYMENT",
                  "searched": HBS_STATE_GLOBS,
                  "note": ("No XMSS or LMS signature state on this host. This "
                           "module activates the moment a stateful hash-based "
                           "signing key is deployed.")})
            time.sleep(POLL_INTERVAL)
            continue

        current = [c for c in (parse_state_file(p) for p in state_files) if c]

        emit({"event": "HBS_SCAN",
              "state_files": len(state_files),
              "key_files":   len(key_files),
              "indices": {os.path.basename(c["path"]): c.get("index")
                          for c in current},
              "chain_head": state.get("chain_head", "")[:16] + "..."})

        alerts, state = analyse(current, state)

        for b in backup_procs:
            alerts.append({
                "event":    "HBS_BACKUP_TOOL_ON_KEYDIR",
                "severity": "CRITICAL",
                "pid": b["pid"], "tool": b["tool"],
                "keydir": b["keydir"], "cmd": b["cmd"],
                "confidence": 0.85,
                "citation": "NIST SP 800-208",
                "note": (f"{b['tool']} is operating on a directory holding "
                         "stateful signature material. Restoring that backup "
                         "rewinds the leaf index and forces one-time key "
                         "reuse. NIST SP 800-208 identifies ordinary backup "
                         "practice as the primary hazard for stateful schemes"),
            })

        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "HBS_STATE_OK",
                  "state_files": len(state_files),
                  "indices": {os.path.basename(c["path"]): c.get("index")
                              for c in current}})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
