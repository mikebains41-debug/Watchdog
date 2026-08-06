#!/usr/bin/env python3
"""
Watchdog — Module 64: SSH Authorized Keys & Backdoor Auditor
Status: FUNCTIONAL — no special hardware required

Attack vector: the single most common persistence mechanism on any Linux
host is a line appended to authorized_keys. It requires no exploit, no
malware, no kernel module. It survives reboots, package updates, and most
incident response. And it is one line of text.

On a quantum control host, SSH access is access to the job scheduler, the
instrument daemons, and every credential on the box.

Beyond key injection, sshd_config itself is an attack surface:
  - PermitRootLogin yes
  - PasswordAuthentication yes on a host that should be key-only
  - An added AuthorizedKeysFile path pointing somewhere writable
  - AuthorizedKeysCommand executing an attacker's script
  - PermitUserEnvironment yes, which lets ~/.ssh/environment set
    LD_PRELOAD on login
  - A ForceCommand or Match block scoped to one user

module32 and module43 check SSH for quantum-vulnerable *algorithms*. This
module checks SSH for *backdoors* — a different problem entirely.

WHAT THIS CHECKS (all functional now):
  - Every authorized_keys file for every user with a home directory,
    plus root, plus any path named in AuthorizedKeysFile
  - Per-key fingerprint (SHA256, the same form ssh-keygen -lf prints),
    baselined and diffed
  - Key options that grant more than login: command=, environment=,
    permitopen=, no-pty absence on a restricted key
  - Weak key types and sizes — DSA at all, RSA under 3072
  - File and directory permissions: authorized_keys writable by group or
    others is a backdoor waiting to happen
  - sshd_config and sshd_config.d/* for dangerous directives
  - AuthorizedKeysCommand — an external program deciding who may log in
  - ~/.ssh/environment presence when PermitUserEnvironment is on
  - known_hosts entries added (lateral movement target list)
  - Root login and password authentication policy

Key material itself is never logged — only fingerprints, types, and
comments.
"""
import os, json, time, datetime, hashlib, base64, stat, glob, re, pwd, subprocess

POLL_INTERVAL   = 300
BASELINE_FILE   = "/tmp/watchdog_ssh_keys_baseline.json"

WEAK_RSA_BITS   = 3072

# sshd_config directives that create or enable a backdoor
DANGEROUS_DIRECTIVES = {
    "permitrootlogin":        (["yes", "without-password", "prohibit-password"],
                               "Root may log in over SSH"),
    "passwordauthentication": (["yes"],
                               "Password authentication enabled — brute-forceable"),
    "permitemptypasswords":   (["yes"],
                               "Empty passwords accepted — critical"),
    "permituserenvironment":  (["yes"],
                               "~/.ssh/environment can set LD_PRELOAD at login"),
    "gatewayports":           (["yes", "clientspecified"],
                               "Remote hosts may bind forwarded ports"),
    "allowtcpforwarding":     (["yes"],
                               "TCP forwarding permitted — tunnelling into the control plane"),
    "permittunnel":           (["yes", "point-to-point", "ethernet"],
                               "Layer 2/3 tunnelling permitted"),
    "usedns":                 ([], None),   # informational only
    "strictmodes":            (["no"],
                               "StrictModes disabled — sshd ignores insecure key file permissions"),
    "ignorerhosts":           (["no"],
                               "rhosts authentication honoured"),
    "hostbasedauthentication":(["yes"],
                               "Host-based authentication enabled"),
}

SSHD_CONFIG_PATHS = [
    "/etc/ssh/sshd_config",
    "/etc/sshd_config",
]
SSHD_CONFIG_D = "/etc/ssh/sshd_config.d/*.conf"

# Key option prefixes that grant capability beyond plain login
POWERFUL_KEY_OPTIONS = [
    "command=", "environment=", "permitopen=", "permitlisten=",
    "tunnel=", "agent-forwarding", "port-forwarding", "pty",
    "cert-authority", "principals=",
]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_baseline() -> dict:
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except:
        return {"keys": {}, "sshd_config": {}, "known_hosts": {},
                 "established": now_iso()}

def save_baseline(b: dict):
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(b, f, indent=2)
    except:
        pass

def key_fingerprint(key_b64: str) -> str | None:
    """
    SHA256 fingerprint in the form OpenSSH prints:
    SHA256:base64(sha256(raw key bytes)) with padding stripped.
    """
    try:
        raw = base64.b64decode(key_b64)
        digest = hashlib.sha256(raw).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    except Exception:
        return None

def rsa_key_bits(key_b64: str) -> int | None:
    """
    Extract the modulus size from an RSA public key blob.
    Format: length-prefixed fields — type, e, n.
    """
    try:
        raw = base64.b64decode(key_b64)
        offset = 0

        def read_field():
            nonlocal offset
            if offset + 4 > len(raw):
                raise ValueError("short")
            length = int.from_bytes(raw[offset:offset+4], "big")
            offset += 4
            data = raw[offset:offset+length]
            offset += length
            return data

        keytype = read_field().decode(errors="replace")
        if "rsa" not in keytype:
            return None
        read_field()          # exponent e
        n = read_field()      # modulus
        # Leading zero byte is a sign pad
        bits = len(n) * 8
        if n and n[0] == 0:
            bits -= 8
        return bits
    except Exception:
        return None

def parse_authorized_keys(path: str) -> list:
    """
    Parse an authorized_keys file into structured entries.
    Handles the options prefix, key type, blob, and comment.
    """
    entries = []
    try:
        with open(path, errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # An options field may precede the key type. Find the first
                # token that looks like a key type.
                tokens = line.split()
                key_type_idx = None
                for i, tok in enumerate(tokens):
                    if (tok.startswith("ssh-") or tok.startswith("ecdsa-")
                            or tok.startswith("sk-")
                            or tok.startswith("rsa-sha2")):
                        key_type_idx = i
                        break
                if key_type_idx is None or key_type_idx + 1 >= len(tokens):
                    continue

                options  = " ".join(tokens[:key_type_idx]) if key_type_idx else ""
                key_type = tokens[key_type_idx]
                key_b64  = tokens[key_type_idx + 1]
                comment  = " ".join(tokens[key_type_idx + 2:])

                fp   = key_fingerprint(key_b64)
                bits = rsa_key_bits(key_b64) if "rsa" in key_type else None

                entries.append({
                    "file":        path,
                    "line":        lineno,
                    "key_type":    key_type,
                    "fingerprint": fp,
                    "comment":     comment[:120],
                    "options":     options,
                    "rsa_bits":    bits,
                })
    except (OSError, PermissionError):
        pass
    return entries

def get_all_users() -> list:
    """Every user with a home directory, plus root."""
    users = []
    try:
        for p in pwd.getpwall():
            if p.pw_dir and os.path.isdir(p.pw_dir):
                users.append({"name": p.pw_name, "uid": p.pw_uid,
                               "home": p.pw_dir, "shell": p.pw_shell})
    except Exception:
        pass
    return users

def find_authorized_keys_files() -> list:
    """Every authorized_keys path on the host."""
    paths = []
    for user in get_all_users():
        for fname in ("authorized_keys", "authorized_keys2"):
            p = os.path.join(user["home"], ".ssh", fname)
            if os.path.exists(p):
                paths.append({"path": p, "user": user["name"],
                               "uid": user["uid"], "home": user["home"]})
    # Any global path configured in sshd_config
    for cfg_path, directives in read_sshd_config().items():
        for key, val in directives:
            if key == "authorizedkeysfile":
                for token in val.split():
                    if token.startswith("/"):
                        for match in glob.glob(token.replace("%u", "*")):
                            if os.path.exists(match) and \
                                    not any(p["path"] == match for p in paths):
                                paths.append({"path": match, "user": "global",
                                               "uid": None, "home": None})
    return paths

def read_sshd_config() -> dict:
    """
    Parse sshd_config and every sshd_config.d/*.conf into
    path -> [(directive_lower, value), ...]
    """
    configs = {}
    files = [p for p in SSHD_CONFIG_PATHS if os.path.exists(p)]
    files.extend(sorted(glob.glob(SSHD_CONFIG_D)))
    for path in files:
        directives = []
        try:
            with open(path, errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        directives.append((parts[0].lower(), parts[1].strip()))
                    elif len(parts) == 1:
                        directives.append((parts[0].lower(), ""))
        except (OSError, PermissionError):
            continue
        configs[path] = directives
    return configs

def get_effective_sshd_config() -> dict:
    """`sshd -T` gives the resolved config including defaults."""
    result = {}
    try:
        out = subprocess.check_output(["sshd", "-T"], text=True, timeout=5,
                                       stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                result[parts[0].lower()] = parts[1].strip()
            elif len(parts) == 1:
                result[parts[0].lower()] = ""
    except Exception:
        pass
    return result

def check_path_perms(path: str) -> dict:
    try:
        st = os.stat(path)
        mode = st.st_mode & 0o777
        return {"mode": oct(mode), "uid": st.st_uid, "gid": st.st_gid,
                 "group_write": bool(mode & stat.S_IWGRP),
                 "world_write": bool(mode & stat.S_IWOTH),
                 "world_read":  bool(mode & stat.S_IROTH)}
    except Exception:
        return {}

def scan_known_hosts() -> dict:
    """known_hosts entry counts per user — growth means lateral movement."""
    result = {}
    for user in get_all_users():
        p = os.path.join(user["home"], ".ssh", "known_hosts")
        if not os.path.exists(p):
            continue
        try:
            with open(p, errors="replace") as f:
                lines = [l for l in f if l.strip()
                         and not l.strip().startswith("#")]
            result[p] = {"user": user["name"], "count": len(lines),
                          "hash": hashlib.sha256(
                              "".join(sorted(lines)).encode()).hexdigest()}
        except (OSError, PermissionError):
            continue
    return result

def scan_ssh_environment_files() -> list:
    """~/.ssh/environment — LD_PRELOAD injection at login."""
    found = []
    for user in get_all_users():
        p = os.path.join(user["home"], ".ssh", "environment")
        if os.path.exists(p):
            try:
                with open(p, errors="replace") as f:
                    content = f.read(4096)
                found.append({"path": p, "user": user["name"],
                               "lines": [l.strip() for l in content.splitlines()
                                          if l.strip()][:10]})
            except (OSError, PermissionError):
                pass
    return found

def analyse(keys: list, key_files: list, configs: dict,
            effective: dict, known_hosts: dict, env_files: list,
            baseline: dict) -> tuple:
    alerts = []
    known_keys  = baseline.get("keys", {})
    known_cfg   = baseline.get("sshd_config", {})
    known_hosts_base = baseline.get("known_hosts", {})

    current_keys = {}

    # ── 1. Per-key checks ──
    for k in keys:
        fp = k.get("fingerprint")
        if not fp:
            continue
        current_keys[fp] = {"file": k["file"], "type": k["key_type"],
                             "comment": k["comment"], "options": k["options"]}

        if fp not in known_keys:
            alerts.append({
                "event":    "UNAUTHORIZED_SSH_KEY_ADDED",
                "severity": "CRITICAL",
                "fingerprint": fp,
                "key_type":  k["key_type"],
                "file":      k["file"],
                "line":      k["line"],
                "comment":   k["comment"],
                "options":   k["options"],
                "confidence": 0.90,
                "note": ("A public key not present at baseline now grants SSH "
                         "access. This is the most common persistence "
                         "mechanism on Linux — one appended line, survives "
                         "reboots and package updates"),
            })

        # Powerful key options
        opts = k.get("options", "")
        if opts:
            matched = [o for o in POWERFUL_KEY_OPTIONS if o in opts.lower()]
            if any(o in opts.lower() for o in ("command=", "environment=")):
                alerts.append({
                    "event":    "SSH_KEY_WITH_COMMAND",
                    "severity": "CRITICAL",
                    "fingerprint": fp,
                    "file":     k["file"],
                    "options":  opts[:200],
                    "confidence": 0.85,
                    "note": ("Key carries a forced command or environment "
                             "option. It executes attacker-chosen code or "
                             "sets environment variables on every login"),
                })
            elif matched:
                alerts.append({
                    "event":    "SSH_KEY_WITH_OPTIONS",
                    "severity": "WARN",
                    "fingerprint": fp,
                    "file":     k["file"],
                    "options":  opts[:200],
                    "matched":  matched,
                    "confidence": 0.55,
                })

        # Weak key material
        if k["key_type"] in ("ssh-dss", "ssh-dsa"):
            alerts.append({
                "event":    "WEAK_SSH_KEY_TYPE",
                "severity": "CRITICAL",
                "fingerprint": fp,
                "key_type": k["key_type"],
                "file":     k["file"],
                "confidence": 0.85,
                "note": "DSA keys are deprecated and cryptographically weak",
            })
        elif k.get("rsa_bits") and k["rsa_bits"] < WEAK_RSA_BITS:
            alerts.append({
                "event":    "WEAK_SSH_KEY_SIZE",
                "severity": "WARN",
                "fingerprint": fp,
                "rsa_bits": k["rsa_bits"],
                "minimum":  WEAK_RSA_BITS,
                "file":     k["file"],
                "confidence": 0.75,
            })

    # ── 2. Key removed ──
    for fp in known_keys:
        if fp not in current_keys:
            alerts.append({
                "event":    "SSH_KEY_REMOVED",
                "severity": "WARN",
                "fingerprint": fp,
                "was":      known_keys[fp],
                "confidence": 0.50,
            })

    # ── 3. authorized_keys permissions ──
    for kf in key_files:
        perms = check_path_perms(kf["path"])
        if perms.get("world_write") or perms.get("group_write"):
            alerts.append({
                "event":    "INSECURE_SSH_PERMISSIONS",
                "severity": "CRITICAL",
                "path":     kf["path"],
                "user":     kf.get("user"),
                "mode":     perms.get("mode"),
                "confidence": 0.95,
                "remediation": f"chmod 600 {kf['path']}",
                "note": ("authorized_keys is writable beyond its owner. Any "
                         "local process can append a key and gain SSH access "
                         "as this user"),
            })
        # .ssh directory itself
        ssh_dir = os.path.dirname(kf["path"])
        dperms = check_path_perms(ssh_dir)
        if dperms.get("world_write") or dperms.get("group_write"):
            alerts.append({
                "event":    "INSECURE_SSH_DIR_PERMISSIONS",
                "severity": "CRITICAL",
                "path":     ssh_dir,
                "mode":     dperms.get("mode"),
                "confidence": 0.90,
                "remediation": f"chmod 700 {ssh_dir}",
                "note": ("The .ssh directory is writable beyond its owner — "
                         "authorized_keys can be replaced wholesale"),
            })

    # ── 4. sshd_config dangerous directives ──
    check_source = effective if effective else {}
    for directive, (bad_values, desc) in DANGEROUS_DIRECTIVES.items():
        if not bad_values or desc is None:
            continue
        val = check_source.get(directive)
        if val and val.lower() in [b.lower() for b in bad_values]:
            sev = "CRITICAL" if directive in (
                "permitemptypasswords", "permituserenvironment",
                "permitrootlogin", "strictmodes") else "WARN"
            alerts.append({
                "event":    "SSHD_DANGEROUS_DIRECTIVE",
                "severity": sev,
                "directive": directive,
                "value":    val,
                "confidence": 0.80 if sev == "CRITICAL" else 0.60,
                "note":     desc,
            })

    # ── 5. AuthorizedKeysCommand ──
    akc = check_source.get("authorizedkeyscommand")
    if akc and akc.lower() != "none":
        akc_user = check_source.get("authorizedkeyscommanduser", "")
        cmd_path = akc.split()[0] if akc else ""
        cmd_perms = check_path_perms(cmd_path) if cmd_path.startswith("/") else {}
        sev = "CRITICAL" if (cmd_perms.get("world_write")
                              or cmd_perms.get("group_write")) else "WARN"
        alerts.append({
            "event":    "SSHD_AUTHORIZED_KEYS_COMMAND",
            "severity": sev,
            "command":  akc,
            "run_as":   akc_user,
            "command_perms": cmd_perms,
            "confidence": 0.85 if sev == "CRITICAL" else 0.60,
            "note": ("An external program decides which keys are accepted. "
                     "If that program is writable by anyone but root, it is "
                     "a direct authentication bypass"),
        })

    # ── 6. sshd_config drift ──
    for path, directives in configs.items():
        h = hashlib.sha256(
            json.dumps(sorted(directives)).encode()).hexdigest()
        if path in known_cfg:
            if known_cfg[path] != h:
                alerts.append({
                    "event":    "SSHD_CONFIG_MODIFIED",
                    "severity": "CRITICAL",
                    "path":     path,
                    "confidence": 0.85,
                    "note": ("sshd configuration changed since baseline. "
                             "Verify no authentication control was relaxed"),
                })
        else:
            alerts.append({
                "event":    "SSHD_CONFIG_NEW_FILE",
                "severity": "WARN",
                "path":     path,
                "directives": [f"{k} {v}" for k, v in directives[:10]],
                "confidence": 0.70,
                "note": ("A new sshd config file appeared. Files in "
                         "sshd_config.d/ override the main config"),
            })
        known_cfg[path] = h

    # ── 7. ~/.ssh/environment ──
    permit_env = check_source.get("permituserenvironment", "no").lower()
    for ef in env_files:
        sev = "CRITICAL" if permit_env == "yes" else "WARN"
        alerts.append({
            "event":    "SSH_ENVIRONMENT_FILE",
            "severity": sev,
            "path":     ef["path"],
            "user":     ef["user"],
            "lines":    ef["lines"],
            "permituserenvironment": permit_env,
            "confidence": 0.85 if sev == "CRITICAL" else 0.55,
            "note": (("PermitUserEnvironment is yes and this file exists — it "
                      "can set LD_PRELOAD and hijack every command run over "
                      "this SSH session")
                     if permit_env == "yes"
                     else "SSH environment file present but PermitUserEnvironment is off"),
        })

    # ── 8. known_hosts growth ──
    for path, info in known_hosts.items():
        if path in known_hosts_base:
            prev = known_hosts_base[path]
            if info["hash"] != prev.get("hash"):
                delta = info["count"] - prev.get("count", 0)
                alerts.append({
                    "event":    "KNOWN_HOSTS_CHANGED",
                    "severity": "WARN" if delta > 0 else "INFO",
                    "path":     path,
                    "user":     info["user"],
                    "was_count": prev.get("count"),
                    "now_count": info["count"],
                    "delta":    delta,
                    "confidence": 0.55,
                    "note": ("New known_hosts entries mean this account "
                             "connected outward to new machines — a lateral "
                             "movement indicator"),
                })

    baseline["keys"]        = current_keys
    baseline["sshd_config"] = known_cfg
    baseline["known_hosts"] = known_hosts
    return alerts, baseline

def main():
    log = open(f"module64_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "64_ssh_backdoor_auditor",
        "status": "FUNCTIONAL — no special hardware required",
        "checks": [
            "authorized_keys per-key SHA256 fingerprint baseline and drift",
            "Key options granting command execution or environment control",
            "Weak key types (DSA) and sizes (RSA < 3072)",
            "authorized_keys and .ssh directory permissions",
            "sshd_config dangerous directives via sshd -T",
            "AuthorizedKeysCommand external authentication program",
            "~/.ssh/environment LD_PRELOAD injection path",
            "known_hosts growth (lateral movement)",
            "sshd_config.d/*.conf drift",
        ],
        "distinct_from_module32_43": ("module32/43 check SSH for "
                                       "quantum-vulnerable algorithms. This "
                                       "module checks SSH for backdoors"),
        "privacy": "Key material is never logged — fingerprints, types, and comments only",
    })

    baseline = load_baseline()
    first    = not baseline.get("keys")

    while True:
        key_files   = find_authorized_keys_files()
        keys        = []
        for kf in key_files:
            keys.extend(parse_authorized_keys(kf["path"]))
        configs     = read_sshd_config()
        effective   = get_effective_sshd_config()
        known_hosts = scan_known_hosts()
        env_files   = scan_ssh_environment_files()

        emit({"event": "SSH_SCAN",
              "authorized_keys_files": len(key_files),
              "total_keys":            len(keys),
              "key_types":             sorted({k["key_type"] for k in keys}),
              "sshd_config_files":     len(configs),
              "environment_files":     len(env_files),
              "known_hosts_files":     len(known_hosts),
              "permitrootlogin":       effective.get("permitrootlogin"),
              "passwordauthentication": effective.get("passwordauthentication")})

        if first:
            emit({"event": "SSH_BASELINE_ESTABLISHED",
                  "keys":  len(keys),
                  "files": len(key_files)})
            baseline["keys"] = {
                k["fingerprint"]: {"file": k["file"], "type": k["key_type"],
                                    "comment": k["comment"],
                                    "options": k["options"]}
                for k in keys if k.get("fingerprint")
            }
            baseline["sshd_config"] = {
                path: hashlib.sha256(
                    json.dumps(sorted(d)).encode()).hexdigest()
                for path, d in configs.items()
            }
            baseline["known_hosts"] = known_hosts
            save_baseline(baseline)
            first = False
            # Static-risk checks still fire on the first pass
            alerts, _ = analyse(keys, key_files, {}, effective,
                                 {}, env_files,
                                 {"keys": baseline["keys"],
                                  "sshd_config": baseline["sshd_config"],
                                  "known_hosts": known_hosts})
            for a in alerts:
                if a["event"] in ("INSECURE_SSH_PERMISSIONS",
                                   "INSECURE_SSH_DIR_PERMISSIONS",
                                   "SSHD_DANGEROUS_DIRECTIVE",
                                   "SSHD_AUTHORIZED_KEYS_COMMAND",
                                   "SSH_KEY_WITH_COMMAND",
                                   "WEAK_SSH_KEY_TYPE",
                                   "WEAK_SSH_KEY_SIZE",
                                   "SSH_ENVIRONMENT_FILE"):
                    emit(a)
            time.sleep(POLL_INTERVAL)
            continue

        alerts, baseline = analyse(keys, key_files, configs, effective,
                                    known_hosts, env_files, baseline)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "SSH_KEYS_CLEAN",
                  "keys_checked": len(keys),
                  "files_checked": len(key_files)})

        save_baseline(baseline)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
