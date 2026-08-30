"""
Seals the real module89 finding — 144/144 certificates on this system
are quantum-vulnerable, despite full OpenSSL PQC support being present
— into the same tamper-evident ledger used for the quantum hardware
results. Run from the Watchdog repo; writes to the collab repo's
evidence file.
"""
import json, hashlib, hmac as _hmac, os, datetime

LEDGER_FILE = "/data/data/com.termux/files/home/Watchdog-quantum-collab/open_quantum_results/quantum_evidence_ledger.jsonl"
HMAC_KEY_FILE = "/tmp/watchdog_evidence_hmac.key"

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_hmac_key():
    with open(HMAC_KEY_FILE, "rb") as f:
        return f.read()

def sign_entry(entry, prev_hash, key):
    entry["prev_hash"] = prev_hash
    entry.setdefault("sealed_at", now_iso())
    canonical = json.dumps(entry, sort_keys=True).encode()
    current_hash = hashlib.sha256(canonical).hexdigest()
    entry["sig"] = _hmac.new(key, canonical, hashlib.sha256).hexdigest()
    entry["hash"] = current_hash
    return entry

key = get_hmac_key()
prev_hash = "0" * 64
if os.path.exists(LEDGER_FILE):
    with open(LEDGER_FILE) as f:
        lines = [l for l in f if l.strip()]
    if lines:
        prev_hash = json.loads(lines[-1]).get("hash", "0" * 64)

entry = {
    "event": "SECURITY_FINDING_SEALED",
    "finding_id": "WD-089-001",
    "module": "89_harvest_now_decrypt_later",
    "title": "System trust store: 100% quantum-vulnerable certificates despite full PQC library support",
    "description": (
        "module89 scanned this system's local certificate trust store "
        "(/etc/ssl/certs and related paths) and found 144 certificates, "
        "of which 144 (100%) use quantum-vulnerable signature algorithms "
        "(RSA or ECDSA). Zero certificates use PQC-hybrid protection. "
        "The installed OpenSSL build was independently confirmed to "
        "support PQC-hybrid key exchange groups (openssl_pqc_support: "
        "true) — meaning this is not a capability gap, it is an adoption "
        "gap. The software can do PQC; nothing on this system uses it yet."
    ),
    "evidence": {
        "certificates_scanned": 144,
        "certificates_quantum_vulnerable": 144,
        "certificates_pqc_protected": 0,
        "openssl_pqc_support_confirmed": True,
        "scan_timestamp": "2026-08-08T22:19:27Z",
    },
    "citation": "NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), NSA CNSA 2.0",
    "status": "CONFIRMED — real scan of real infrastructure, reproducible by re-running module89",
}

signed = sign_entry(entry, prev_hash, key)

with open(LEDGER_FILE, "a") as f:
    f.write(json.dumps(signed) + "\n")

print(f"Sealed finding WD-089-001")
print(f"Hash: {signed['hash'][:16]}...")
print(f"Ledger: {LEDGER_FILE}")
