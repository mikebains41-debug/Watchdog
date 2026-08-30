#!/usr/bin/env python3
"""
Watchdog — Module 32: Post-Quantum Crypto Readiness
NIST PQC standards finalized Aug 2024:
  ML-KEM  (FIPS 203) — key encapsulation, replaces ECDH/RSA-KEM
  ML-DSA  (FIPS 204) — digital signatures, replaces ECDSA/RSA-PSS
  SLH-DSA (FIPS 205) — hash-based signatures
  FN-DSA  (FIPS 206) — Falcon lattice signatures
NSA CNSA 2.0 mandates migration by 2030.
Google projects 256-bit ECC broken by 2029.
"""
import subprocess, datetime, json, os, re, glob
from collections import deque

QUANTUM_VULNERABLE = [
    "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
]
PQC_SAFE_INDICATORS = ["sntrup761", "mlkem", "kyber", "dilithium", "falcon", "sphincs"]
WEAK_RSA_BITS = 3072   # RSA below this is critically weak

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

def check_sshd_config():
    issues = []
    out = run(["sshd", "-T"])
    if not out:
        out_file = ""
        for path in ["/etc/ssh/sshd_config", "/etc/sshd_config"]:
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        out_file = f.read()
                except:
                    pass
        out = out_file

    for alg in QUANTUM_VULNERABLE:
        if alg.lower() in out.lower():
            issues.append(f"sshd allows quantum-vulnerable algorithm: {alg}")

    # Check if any PQC hybrid is enabled
    pqc_found = any(p in out.lower() for p in PQC_SAFE_INDICATORS)
    if not pqc_found:
        issues.append("sshd: no PQC-safe key exchange algorithms detected")
    return issues

def check_ssh_host_keys():
    issues = []
    key_paths = glob.glob("/etc/ssh/ssh_host_*_key.pub")
    for kp in key_paths:
        out = run(["ssh-keygen", "-l", "-f", kp])
        if "RSA" in out:
            # Extract bit size
            m = re.search(r'(\d+)', out)
            if m:
                bits = int(m.group(1))
                if bits < WEAK_RSA_BITS:
                    issues.append(f"Host key {os.path.basename(kp)}: RSA {bits}-bit (quantum-vulnerable, <{WEAK_RSA_BITS})")
                else:
                    issues.append(f"Host key {os.path.basename(kp)}: RSA {bits}-bit (quantum-vulnerable regardless of size)")
        if "ECDSA" in out or "ED25519" in out:
            issues.append(f"Host key {os.path.basename(kp)}: classical ECC (quantum-vulnerable)")
    return issues

def check_tls_certs():
    issues = []
    cert_dirs = ["/etc/ssl/certs", "/etc/pki/tls/certs", "/usr/share/ca-certificates"]
    checked = 0
    for d in cert_dirs:
        if not os.path.isdir(d):
            continue
        for cert in glob.glob(os.path.join(d, "*.pem"))[:20]:   # Sample first 20
            out = run(["openssl", "x509", "-in", cert,
                       "-noout", "-subject", "-pubkey", "-text"])
            if "rsaEncryption" in out:
                m = re.search(r'Public-Key:\s*\((\d+)', out)
                bits = int(m.group(1)) if m else 0
                if bits < 4096:
                    issues.append(f"{os.path.basename(cert)}: RSA {bits}-bit (quantum-vulnerable)")
                    checked += 1
            if "id-ecPublicKey" in out or "prime256v1" in out or "secp384r1" in out:
                issues.append(f"{os.path.basename(cert)}: ECC cert (quantum-vulnerable)")
                checked += 1
            if checked >= 5:
                break
        if checked >= 5:
            break
    return issues

def check_openssl():
    issues = []
    version_out = run(["openssl", "version"])
    if not version_out:
        return ["openssl not found"]

    # Check if OQS (Open Quantum Safe) provider is available
    oqs_out = run(["openssl", "list", "-providers"])
    has_oqs = "oqs" in oqs_out.lower() or "liboqs" in oqs_out.lower()
    if not has_oqs:
        issues.append(f"OpenSSL ({version_out}): OQS provider not installed — ML-KEM/ML-DSA unavailable")
    else:
        issues.append(f"OpenSSL ({version_out}): OQS provider present — PQC algorithms available")

    # Check active TLS 1.3 cipher suites
    ciphers_out = run(["openssl", "ciphers", "-v", "-tls1_3"])
    pqc_tls = any(p in ciphers_out.lower() for p in PQC_SAFE_INDICATORS)
    if not pqc_tls:
        issues.append("TLS 1.3 cipher suites: no PQC hybrid detected")
    return issues

def main():
    log = open(f"module32_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({"event": "RUN_START", "module": "32_pqc_readiness",
          "context": "NSA CNSA 2.0 deadline 2030, Google 256-bit ECC break prediction 2029"})

    alerts = 0

    for issue in check_sshd_config():
        alerts += 1
        emit({"event": "PQC_SSH_DOWNGRADE", "severity": "WARN",
              "issue": issue, "confidence": 0.85,
              "remediation": "Add sntrup761x25519-sha512 to KexAlgorithms in sshd_config"})

    for issue in check_ssh_host_keys():
        alerts += 1
        emit({"event": "PQC_HOST_KEY_VULNERABLE", "severity": "WARN",
              "issue": issue, "confidence": 0.90,
              "remediation": "Generate ed25519 or wait for OpenSSH PQC host key support"})

    for issue in check_tls_certs():
        alerts += 1
        emit({"event": "PQC_TLS_CERT_VULNERABLE", "severity": "WARN",
              "issue": issue, "confidence": 0.80,
              "remediation": "Replace with ML-DSA or hybrid classical+PQC certificate"})

    for issue in check_openssl():
        alerts += 1
        emit({"event": "PQC_OPENSSL_STATUS", "severity": "INFO",
              "issue": issue, "confidence": 0.75})

    emit({"event": "RUN_END", "alerts": alerts})
    log.close()

if __name__ == "__main__":
    main()
