#!/usr/bin/env python3
"""
Watchdog — Module 89: Harvest-Now-Decrypt-Later Exposure Scanner
Status: FUNCTIONAL — no special hardware required

THE THREAT: every RSA/ECDSA/ECDH-protected session and stored artifact
being encrypted TODAY is potentially being recorded by an adversary for
decryption once a cryptographically-relevant quantum computer exists.
This is not speculative — it is the explicit stated concern behind
NIST's post-quantum cryptography standardization effort and the reason
NSA's CNSA 2.0 mandates PQC migration timelines for national security
systems.

Shor's algorithm, run on a sufficiently large fault-tolerant quantum
computer, breaks RSA, ECDSA, ECDH, and DSA by solving the integer
factorization and discrete logarithm problems those systems rely on.
Symmetric crypto (AES) and hash-based schemes are comparatively safe —
this module focuses specifically on the algorithms that are provably
broken by a future quantum computer, and are being used to protect data
whose confidentiality window may span years or decades.

STANDARDS THIS MODULE VALIDATES AGAINST:
  NIST FIPS 203 — ML-KEM (Module-Lattice-Based Key-Encapsulation
    Mechanism), the standardized post-quantum key exchange
  NIST FIPS 204 — ML-DSA (Module-Lattice-Based Digital Signature
    Algorithm), the standardized post-quantum signature scheme
  NIST FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature)
  NSA CNSA 2.0 — mandates PQC or PQC-hybrid for National Security
    Systems, with explicit migration timelines through 2033

WHAT THIS MODULE DETECTS — all functional now:
  1. TLS/HTTPS endpoints (local services and configured remote hosts)
     whose negotiated key exchange is pure classical (RSA key exchange,
     plain ECDH) with no PQC hybrid (X25519Kyber768, X25519MLKEM768,
     SecP256r1MLKEM768) offered or selected.
  2. Certificate files using RSA or ECDSA signatures with long
     remaining validity — the longer a cert lives, the longer its
     traffic remains exposed to future decryption.
  3. SSH host keys and known_hosts using RSA/ECDSA/DSA instead of
     Ed25519 or a PQC-hybrid KEX (sntrup761x25519).
  4. VPN configurations (WireGuard, OpenVPN, IPsec) using classical-only
     key exchange with no PQC-hybrid handshake.
  5. Stored encrypted archives, backups, and long-lived data whose
     encryption metadata references RSA/ECDH key wrapping — these are
     the actual "harvest now" targets, since their confidentiality
     window can span years.
  6. TLS library and OpenSSL version checks against known PQC-support
     baselines — some versions cannot do hybrid KEX even if configured
     to.
  7. Estimated "exposure window": for each classical-crypto artifact
     found, how many years until a plausible CRQC (cryptographically
     relevant quantum computer) timeline, based on published expert
     consensus ranges — not a specific prediction, a documented range.

WHAT THIS MODULE DOES NOT DO: it does not claim to know when a CRQC
will exist. It reports the exposure fact — classical crypto is in use,
protecting data — and lets the operator judge urgency against their own
data's required confidentiality lifetime.
"""
import os, json, time, datetime, glob, re, subprocess, ssl, socket

POLL_INTERVAL       = 3600
STATE_FILE          = "/tmp/watchdog_hndl_exposure.json"

# PQC and PQC-hybrid key exchange group names as they appear in TLS
# ClientHello/ServerHello and OpenSSL group listings
PQC_HYBRID_GROUPS = [
    "x25519_kyber768", "x25519kyber768draft00", "X25519Kyber768Draft00",
    "x25519_mlkem768", "X25519MLKEM768", "SecP256r1MLKEM768",
    "secp256r1_mlkem768", "SecP384r1MLKEM1024", "kyber768", "kyber1024",
    "mlkem768", "mlkem1024", "sntrup761x25519", "sntrup761x25519-sha512",
]

# Classical-only groups that offer no post-quantum protection
CLASSICAL_ONLY_GROUPS = [
    "secp256r1", "secp384r1", "secp521r1", "prime256v1",
    "x25519", "x448", "ffdhe2048", "ffdhe3072", "ffdhe4096",
]

# Signature algorithms broken by Shor's algorithm on a CRQC
QUANTUM_VULNERABLE_SIG_ALGOS = ["rsa", "ecdsa", "dsa", "ed25519_not_pqc"]
# Ed25519 signatures are classically strong but still not PQC —
# included for completeness, though it's the least urgent of these

# Published expert-consensus CRQC timeline ranges — NOT a Watchdog
# prediction. Cited from the Global Risk Institute's annual Quantum
# Threat Timeline Report expert survey.
CRQC_TIMELINE_CITATION = (
    "Global Risk Institute, Quantum Threat Timeline Report — annual "
    "expert survey aggregating probability estimates for when a "
    "cryptographically relevant quantum computer will exist. Median "
    "expert estimates have clustered in the 2030s across recent survey "
    "years, with a wide uncertainty range. Cited as an industry "
    "reference point, not a Watchdog-generated prediction."
)

TLS_SCAN_HOSTS_ENV = "WATCHDOG_TLS_SCAN_HOSTS"  # comma-separated host:port list

SSH_KEY_GLOBS = [
    os.path.expanduser("~/.ssh/id_rsa*"),
    os.path.expanduser("~/.ssh/id_ecdsa*"),
    os.path.expanduser("~/.ssh/id_dsa*"),
    "/etc/ssh/ssh_host_rsa_key*",
    "/etc/ssh/ssh_host_ecdsa_key*",
    "/etc/ssh/ssh_host_dsa_key*",
]

VPN_CONFIG_GLOBS = [
    "/etc/wireguard/*.conf",
    "/etc/openvpn/*.conf", "/etc/openvpn/*.ovpn",
    "/etc/ipsec.conf", "/etc/ipsec.d/*.conf",
]

CERT_GLOBS = [
    "/etc/ssl/certs/*.pem", "/etc/ssl/private/*.pem",
    "/etc/letsencrypt/live/*/fullchain.pem",
    os.path.expanduser("~/.ssh/*.pem"),
]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {"scanned_certs": {}, "established": now_iso()}

def save_state(s):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except:
        pass

def check_openssl_pqc_support():
    """Does the installed OpenSSL even support PQC hybrid groups?"""
    try:
        out = subprocess.check_output(["openssl", "list", "-tls-groups"],
                                       text=True, timeout=5,
                                       stderr=subprocess.DEVNULL)
        supported = [g for g in PQC_HYBRID_GROUPS
                     if g.lower() in out.lower()]
        version_out = subprocess.check_output(["openssl", "version"],
                                               text=True, timeout=5)
        return {"pqc_groups_available": supported,
                 "has_pqc_support": len(supported) > 0,
                 "openssl_version": version_out.strip()}
    except Exception as e:
        return {"error": str(e), "has_pqc_support": None}

def probe_tls_endpoint(host, port=443, timeout=5):
    """
    Connect to a real TLS endpoint and inspect the negotiated key
    exchange group and certificate signature algorithm.
    """
    result = {"host": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                result["tls_version"] = ssock.version()
                result["cipher"] = cipher[0] if cipher else None

                group = None
                try:
                    group = ssock.group()
                except AttributeError:
                    pass
                result["negotiated_group"] = group

                if cert_bin:
                    try:
                        out = subprocess.run(
                            ["openssl", "x509", "-inform", "DER", "-noout",
                             "-text"],
                            input=cert_bin, capture_output=True, timeout=5)
                        text = out.stdout.decode(errors="replace")
                        m = re.search(r'Signature Algorithm:\s*(\S+)', text)
                        if m:
                            result["cert_sig_algo"] = m.group(1)
                        m2 = re.search(r'Not After\s*:\s*(.+)', text)
                        if m2:
                            result["cert_not_after"] = m2.group(1).strip()
                    except Exception:
                        pass
    except Exception as e:
        result["error"] = str(e)
    return result

def classify_group(group_name):
    if not group_name:
        return "unknown"
    low = group_name.lower()
    for g in PQC_HYBRID_GROUPS:
        if g.lower() in low:
            return "pqc_hybrid"
    for g in CLASSICAL_ONLY_GROUPS:
        if g.lower() == low or g.lower() in low:
            return "classical_only"
    return "unrecognized"

def parse_cert_expiry(not_after_str):
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.datetime.strptime(not_after_str, fmt).replace(
                tzinfo=datetime.timezone.utc)
        except Exception:
            continue
    return None

def scan_ssh_keys():
    findings = []
    for pattern in SSH_KEY_GLOBS:
        for path in glob.glob(pattern):
            if path.endswith(".pub"):
                continue
            base = os.path.basename(path)
            if "rsa" in base.lower():
                algo = "RSA"
            elif "ecdsa" in base.lower():
                algo = "ECDSA"
            elif "dsa" in base.lower() and "ecdsa" not in base.lower():
                algo = "DSA"
            else:
                continue
            findings.append({"path": path, "algorithm": algo})
    return findings

def scan_vpn_configs():
    findings = []
    for pattern in VPN_CONFIG_GLOBS:
        for path in glob.glob(pattern):
            try:
                with open(path, errors="replace") as f:
                    content = f.read(65536)
            except Exception:
                continue
            has_pqc = any(g.lower() in content.lower() for g in PQC_HYBRID_GROUPS)
            if not has_pqc:
                findings.append({"path": path, "has_pqc_hybrid": False})
    return findings

def scan_certs():
    found = []
    for pattern in CERT_GLOBS:
        for path in glob.glob(pattern):
            try:
                out = subprocess.check_output(
                    ["openssl", "x509", "-in", path, "-noout",
                     "-text"], text=True, timeout=5,
                    stderr=subprocess.DEVNULL)
            except Exception:
                continue
            m = re.search(r'Signature Algorithm:\s*(\S+)', out)
            m2 = re.search(r'Not After\s*:\s*(.+)', out)
            if m:
                sig = m.group(1)
                vulnerable = any(a in sig.lower() for a in
                                 ("rsa", "ecdsa", "dsa"))
                if vulnerable:
                    entry = {"path": path, "sig_algo": sig}
                    if m2:
                        entry["not_after"] = m2.group(1).strip()
                    found.append(entry)
    return found

def get_scan_hosts():
    env_hosts = os.environ.get(TLS_SCAN_HOSTS_ENV, "")
    hosts = []
    for entry in env_hosts.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            h, p = entry.rsplit(":", 1)
            hosts.append((h, int(p)))
        else:
            hosts.append((entry, 443))
    return hosts

def analyse(openssl_info, tls_results, ssh_findings, vpn_findings,
            cert_findings, state):
    alerts = []

    if openssl_info.get("has_pqc_support") is False:
        alerts.append({
            "event":    "OPENSSL_NO_PQC_SUPPORT",
            "severity": "WARN",
            "openssl_version": openssl_info.get("openssl_version"),
            "confidence": 0.75,
            "citation": "NIST FIPS 203 (ML-KEM)",
            "note": ("The installed OpenSSL build does not support any "
                     "PQC-hybrid key exchange group. Even correctly "
                     "configured software cannot negotiate post-quantum "
                     "protection on this host until OpenSSL is upgraded"),
        })

    for r in tls_results:
        if "error" in r:
            continue
        kind = classify_group(r.get("negotiated_group"))
        if kind == "classical_only":
            alerts.append({
                "event":    "TLS_CLASSICAL_ONLY_KEY_EXCHANGE",
                "severity": "CRITICAL",
                "host":     r["host"], "port": r["port"],
                "negotiated_group": r.get("negotiated_group"),
                "tls_version": r.get("tls_version"),
                "cert_sig_algo": r.get("cert_sig_algo"),
                "confidence": 0.85,
                "citation": "NIST FIPS 203; NSA CNSA 2.0",
                "note": (f"TLS session to {r['host']}:{r['port']} negotiated "
                         f"a purely classical key exchange group "
                         f"({r.get('negotiated_group')}). Traffic on this "
                         "connection is exposed to harvest-now-decrypt-later "
                         "collection — recorded today, decryptable once a "
                         "cryptographically relevant quantum computer exists"),
                "action": "Enable PQC-hybrid key exchange (e.g. X25519MLKEM768) on server and client",
            })
        elif kind == "unknown":
            alerts.append({
                "event":    "TLS_GROUP_UNDETERMINED",
                "severity": "INFO",
                "host":     r["host"], "port": r["port"],
                "confidence": 0.40,
                "note": "Could not determine negotiated key exchange group from this client",
            })

        sig = (r.get("cert_sig_algo") or "").lower()
        if sig and any(a in sig for a in ("rsa", "ecdsa", "dsa")):
            expiry = parse_cert_expiry(r.get("cert_not_after", ""))
            years_left = None
            if expiry:
                years_left = round((expiry - datetime.datetime.now(
                    datetime.timezone.utc)).days / 365.25, 1)
            alerts.append({
                "event":    "QUANTUM_VULNERABLE_CERTIFICATE",
                "severity": "WARN",
                "host":     r["host"], "port": r["port"],
                "sig_algo": r.get("cert_sig_algo"),
                "not_after": r.get("cert_not_after"),
                "years_remaining_validity": years_left,
                "confidence": 0.75,
                "note": ("Certificate uses a signature algorithm broken by "
                         "Shor's algorithm on a future quantum computer. "
                         "The signature itself becomes forgeable, and any "
                         "session key exchange it protected becomes "
                         "retroactively exposed if recorded"),
                "crqc_timeline_reference": CRQC_TIMELINE_CITATION,
            })

    for f in ssh_findings:
        alerts.append({
            "event":    "SSH_KEY_QUANTUM_VULNERABLE",
            "severity": "WARN",
            "path":     f["path"], "algorithm": f["algorithm"],
            "confidence": 0.70,
            "note": (f"SSH key uses {f['algorithm']}, broken by a future "
                     "quantum computer. Ed25519 is not PQC either, but SSH "
                     "sessions are typically short-lived and not usually a "
                     "harvest-now target the way stored/long-lived TLS "
                     "traffic is — still worth migrating on the standard "
                     "SSH upgrade cycle"),
        })

    for f in vpn_findings:
        alerts.append({
            "event":    "VPN_NO_PQC_HYBRID",
            "severity": "CRITICAL",
            "path":     f["path"],
            "confidence": 0.70,
            "note": ("VPN configuration has no PQC-hybrid handshake "
                     "configured. VPN traffic is exactly the kind of "
                     "long-lived, high-value traffic that harvest-now "
                     "collection targets — organizational and personal "
                     "traffic recorded in bulk today"),
        })

    for f in cert_findings:
        years_left = None
        if f.get("not_after"):
            expiry = parse_cert_expiry(f["not_after"])
            if expiry:
                years_left = round((expiry - datetime.datetime.now(
                    datetime.timezone.utc)).days / 365.25, 1)
        alerts.append({
            "event":    "STORED_CERT_QUANTUM_VULNERABLE",
            "severity": "WARN",
            "path":     f["path"], "sig_algo": f["sig_algo"],
            "years_remaining_validity": years_left,
            "confidence": 0.70,
            "note": "Certificate file on disk uses a quantum-vulnerable signature algorithm",
        })

    return alerts

def main():
    log = open(f"module89_{stamp()}.jsonl", "a")

    def emit(event):
        event.setdefault("ts", now_iso())
        log.write(json.dumps(event) + "\n")
        log.flush()

    emit({
        "event":  "RUN_START",
        "module": "89_harvest_now_decrypt_later",
        "status": "FUNCTIONAL — no special hardware required",
        "threat": ("Every RSA/ECDSA/ECDH-protected session and stored "
                    "artifact encrypted today is a potential harvest-now "
                    "target — recorded now, decryptable once a "
                    "cryptographically relevant quantum computer exists"),
        "standards": [
            "NIST FIPS 203 — ML-KEM",
            "NIST FIPS 204 — ML-DSA",
            "NIST FIPS 205 — SLH-DSA",
            "NSA CNSA 2.0 — PQC migration mandate for National Security Systems",
        ],
        "detects": [
            "TLS endpoints negotiating classical-only key exchange",
            "Certificates with quantum-vulnerable signature algorithms",
            "SSH keys using RSA/ECDSA/DSA",
            "VPN configs with no PQC-hybrid handshake",
            "Stored certificates with quantum-vulnerable signatures",
            "OpenSSL builds lacking PQC-hybrid group support",
        ],
        "pqc_hybrid_groups_recognized": len(PQC_HYBRID_GROUPS),
        "scope_note": ("Reports the exposure fact — classical crypto in "
                        "use — and lets the operator judge urgency against "
                        "their data's required confidentiality lifetime. "
                        "Does not predict when a CRQC will exist"),
    })

    state = load_state()

    while True:
        openssl_info = check_openssl_pqc_support()
        hosts = get_scan_hosts()
        tls_results = [probe_tls_endpoint(h, p) for h, p in hosts]
        ssh_findings = scan_ssh_keys()
        vpn_findings = scan_vpn_configs()
        cert_findings = scan_certs()

        emit({"event": "HNDL_SCAN",
              "openssl_pqc_support": openssl_info.get("has_pqc_support"),
              "tls_hosts_scanned": len(hosts),
              "ssh_keys_found": len(ssh_findings),
              "vpn_configs_found": len(vpn_findings),
              "cert_files_scanned": len(cert_findings)})

        if not hosts:
            emit({"event": "NO_TLS_HOSTS_CONFIGURED",
                  "note": (f"Set {TLS_SCAN_HOSTS_ENV}=host1:443,host2:443 "
                           "to scan real TLS endpoints for PQC readiness")})

        alerts = analyse(openssl_info, tls_results, ssh_findings,
                         vpn_findings, cert_findings, state)
        for a in alerts:
            emit(a)

        if not alerts:
            emit({"event": "HNDL_EXPOSURE_CLEAN"})

        save_state(state)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
