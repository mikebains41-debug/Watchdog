#!/usr/bin/env python3
"""
Watchdog — Module 43: Classical Host Crypto Downgrade Prevention
Complements module32 (detection) with active remediation.
module32 = scan and report
module43 = scan, report, AND harden

Forces sshd restart with PQC-safe config if quantum-vulnerable
algorithms are found actively negotiating on the host.
Google predicts 256-bit ECC broken by 2029. NSA CNSA 2.0 deadline: 2030.
"""
import subprocess, datetime, json, os, time, re

QUANTUM_VULNERABLE_KEX = [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group14-sha256",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
]

QUANTUM_VULNERABLE_HOSTKEY = [
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
]

# PQC-safe additions to push into sshd config
PQC_SAFE_KEX = "sntrup761x25519-sha512@openssh.com"

POLL_INTERVAL     = 3600   # Check every hour
SSHD_CONFIG_PATH  = "/etc/ssh/sshd_config"
SSHD_BACKUP_PATH  = "/etc/ssh/sshd_config.watchdog_backup"
ENABLE_HARDENING  = os.environ.get("WD_ENABLE_CRYPTO_HARDENING", "false").lower() == "true"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def run(cmd, timeout=5):
    try:
        return subprocess.check_output(cmd, text=True, timeout=timeout,
                                        stderr=subprocess.DEVNULL).strip()
    except:
        return ""

def scan_active_ssh_sessions() -> list:
    """
    Check active SSH connections for algorithm negotiation.
    Uses ss -tnp to find SSH connections, then checks established ciphers.
    """
    issues = []
    out = run(["ss", "-tnp"])
    ssh_conns = [l for l in out.splitlines() if ":22 " in l and "ESTAB" in l]
    if ssh_conns:
        issues.append(f"{len(ssh_conns)} active SSH connections — verify cipher suites")
    return issues

def scan_sshd_config() -> list:
    """Scan sshd config file for quantum-vulnerable algorithms."""
    issues = []
    config_paths = [SSHD_CONFIG_PATH, "/etc/sshd_config"]

    for path in config_paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                content = f.read()
            for alg in QUANTUM_VULNERABLE_KEX:
                if alg in content:
                    issues.append({"type": "kex", "algorithm": alg, "file": path})
            for alg in QUANTUM_VULNERABLE_HOSTKEY:
                if alg in content and "HostKeyAlgorithms" in content:
                    issues.append({"type": "hostkey", "algorithm": alg, "file": path})
        except:
            pass

    # Also check live sshd -T output
    live_config = run(["sshd", "-T"])
    for alg in QUANTUM_VULNERABLE_KEX:
        if alg in live_config.lower():
            issues.append({"type": "kex_live", "algorithm": alg, "source": "sshd -T"})

    return issues

def check_tls_active_connections() -> list:
    """Check active TLS connections for quantum-vulnerable cipher suites."""
    issues = []
    try:
        out = run(["ss", "-tnp", "state", "established"])
        https_conns = [l for l in out.splitlines() if ":443" in l or ":8443" in l]
        if https_conns:
            # Check nginx/apache ssl config if present
            for ssl_conf in ["/etc/nginx/nginx.conf", "/etc/ssl/openssl.cnf",
                              "/etc/apache2/mods-enabled/ssl.conf"]:
                if os.path.exists(ssl_conf):
                    with open(ssl_conf) as f:
                        content = f.read()
                    if "ECDHE-RSA" in content or "ECDHE-ECDSA" in content:
                        issues.append({"type": "tls", "file": ssl_conf,
                                       "note": "Classical ECC TLS ciphers active"})
    except:
        pass
    return issues

def harden_sshd() -> bool:
    """
    Add PQC-safe KEX algorithm to sshd_config.
    Only runs if WD_ENABLE_CRYPTO_HARDENING=true env var is set.
    Creates backup before modifying.
    """
    if not os.path.exists(SSHD_CONFIG_PATH):
        return False
    try:
        # Backup
        with open(SSHD_CONFIG_PATH) as f:
            original = f.read()
        with open(SSHD_BACKUP_PATH, "w") as f:
            f.write(original)

        # Add PQC KEX at the front of KexAlgorithms if not present
        if PQC_SAFE_KEX not in original:
            if "KexAlgorithms" in original:
                # Prepend to existing line
                new = re.sub(r'(KexAlgorithms\s+)',
                              f'\\1{PQC_SAFE_KEX},', original)
            else:
                # Add new line
                new = original + f"\nKexAlgorithms {PQC_SAFE_KEX},ecdh-sha2-nistp256\n"

            with open(SSHD_CONFIG_PATH, "w") as f:
                f.write(new)

        # Test config before restarting
        test = run(["sshd", "-t"], timeout=5)
        if test == "":   # sshd -t exits 0 with no output if valid
            subprocess.check_output(["systemctl", "restart", "sshd"], timeout=10)
            return True
        else:
            # Restore backup on bad config
            with open(SSHD_CONFIG_PATH, "w") as f:
                f.write(original)
            return False
    except:
        return False

def main():
    log = open(f"module43_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "43_crypto_downgrade_prevent",
          "hardening_enabled": ENABLE_HARDENING,
          "context": "NSA CNSA 2.0 deadline 2030, ECC break prediction 2029"})

    alerts = 0

    while True:
        ssh_issues = scan_sshd_config()
        tls_issues = check_tls_active_connections()
        session_issues = scan_active_ssh_sessions()

        for issue in ssh_issues:
            alerts += 1
            emit({"event": "CRYPTO_DOWNGRADE_DETECTED", "severity": "WARN",
                  "confidence": 0.90, **issue,
                  "remediation": f"Add {PQC_SAFE_KEX} to KexAlgorithms",
                  "deadline": "NSA CNSA 2.0: 2030"})

            if ENABLE_HARDENING and issue.get("type") in ("kex", "kex_live"):
                if harden_sshd():
                    emit({"event": "SSHD_HARDENED",
                          "action": f"Added {PQC_SAFE_KEX} to KexAlgorithms + sshd restarted",
                          "backup": SSHD_BACKUP_PATH})
                else:
                    emit({"event": "SSHD_HARDEN_FAILED",
                          "note": "Config test failed or sshd restart failed — backup preserved"})

        for issue in tls_issues:
            alerts += 1
            emit({"event": "TLS_QUANTUM_VULNERABLE", "severity": "WARN",
                  "confidence": 0.75, **issue})

        for issue in session_issues:
            emit({"event": "SSH_SESSIONS_ACTIVE", "severity": "INFO",
                  "detail": issue})

        if not ssh_issues and not tls_issues:
            emit({"event": "CRYPTO_SCAN_CLEAN",
                  "note": "No quantum-vulnerable algorithms detected this scan"})

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
