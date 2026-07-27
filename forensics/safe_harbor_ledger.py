# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
Watchdog AIDR v2.0 - AI Safe-Harbor Ledger
Cryptographically chained compliance event ledger for auditor delivery.
HMAC-SHA256 signed blocks. Every event is tamper-evident and exportable
as a verified proof bundle for compliance reviews.

This is a compliance EVIDENCE tool. It does not constitute SOC2 or
ISO 27001 certification. Formal certification requires an accredited auditor.

FIXED: previously fell back to a hardcoded, public
"watchdog-default-key-change-in-production" string whenever
WATCHDOG_HARBOR_KEY wasn't set. Since that fallback string is sitting
in this file's own source history, anyone who has ever seen this
repository could forge a block that verifies as "validly signed" under
the default key. A silent insecure fallback in a module whose entire
purpose is cryptographic tamper-evidence defeats that purpose. Now
refuses to construct at all without a real key -- same "refuse rather
than guess" pattern used throughout this project (e.g.
VRAMResidualDetector's strict mode, RemediationEngine's kill_process
refusing without a named target).
"""
import json, hmac, hashlib, time, os
from datetime import datetime, timezone


class SafeHarborKeyNotConfigured(RuntimeError):
    """Raised when no real signing key is available. Deliberately not
    swallowed -- a caller must either set WATCHDOG_HARBOR_KEY or pass
    signing_key explicitly."""


class AISafeHarborLedger:
    def __init__(self, signing_key=None, ledger_path=None):
        key = signing_key or os.environ.get("WATCHDOG_HARBOR_KEY")
        if not key:
            raise SafeHarborKeyNotConfigured(
                "AISafeHarborLedger requires a real signing key. Set the "
                "WATCHDOG_HARBOR_KEY environment variable, or pass "
                "signing_key= explicitly. Refusing to fall back to a "
                "default key, since that key has been publicly visible "
                "in this project's source and would let anyone forge a "
                "'validly signed' block."
            )
        self.secret_key = key.encode() if isinstance(key, str) else key
        self.ledger_path = ledger_path or "watchdog_data/safe_harbor_ledger.jsonl"
        os.makedirs(os.path.dirname(self.ledger_path) if os.path.dirname(self.ledger_path) else ".", exist_ok=True)
        self.last_block_hash = self._get_last_hash()
        self._seq = self._count_entries()

    def _sign(self, data_bytes):
        return hmac.new(self.secret_key, data_bytes, hashlib.sha256).hexdigest()

    def _get_last_hash(self):
        if not os.path.exists(self.ledger_path):
            return "0" * 64
        try:
            last = None
            with open(self.ledger_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last = line
            if last:
                return json.loads(last).get("cryptographic_signature", "0" * 64)
        except Exception:
            pass
        return "0" * 64

    def _count_entries(self):
        if not os.path.exists(self.ledger_path):
            return 0
        count = 0
        with open(self.ledger_path) as f:
            for line in f:
                if line.strip():
                    count += 1
        return count

    def append(self, alert_type, engine_category, affected_gpus, metrics,
                cvss_score=None, cve=None, framework_controls=None):
        self._seq += 1
        payload = {
            "seq": self._seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": alert_type,
            "engine_category": engine_category,
            "affected_gpus": affected_gpus,
            "telemetry_metrics": metrics,
            "cvss_score": cvss_score,
            "cve_reference": cve,
            "framework_controls": framework_controls or [],
            "parent_block_hash": self.last_block_hash,
            "system": "Watchdog AIDR v2.0",
            "cve_baseline": "CVE-2048350 (pending assignment)",
        }
        serialized = json.dumps(payload, sort_keys=True).encode()
        signature = self._sign(serialized)
        block = {"payload": payload, "cryptographic_signature": signature}
        with open(self.ledger_path, "a") as f:
            f.write(json.dumps(block) + "\n")
        self.last_block_hash = signature
        return signature

    def verify_chain(self):
        if not os.path.exists(self.ledger_path):
            return True, "EMPTY_LEDGER"
        entries = []
        with open(self.ledger_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        if not entries:
            return True, "EMPTY_LEDGER"
        prev_hash = "0" * 64
        for entry in entries:
            payload = entry["payload"]
            stored_sig = entry["cryptographic_signature"]
            if payload["parent_block_hash"] != prev_hash:
                return False, f"CHAIN_BREAK at seq {payload['seq']}"
            computed = self._sign(json.dumps(payload, sort_keys=True).encode())
            if computed != stored_sig:
                return False, f"TAMPER_DETECTED at seq {payload['seq']}"
            prev_hash = stored_sig
        return True, f"CHAIN_VALID — {len(entries)} blocks verified"

    def export_auditor_proof_bundle(self, output_path=None):
        entries = []
        if os.path.exists(self.ledger_path):
            with open(self.ledger_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        valid, msg = self.verify_chain()
        bundle = {
            "export_metadata": {
                "format_version": "1.0.0",
                "authority": "Watchdog AIDR v2.0 Cryptographic Evidence System",
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "chain_status": msg,
                "chain_valid": valid,
                "total_events": len(entries),
                "disclaimer": (
                    "This bundle is compliance EVIDENCE, not certification. "
                    "Formal SOC2 Type II or ISO 27001 certification requires "
                    "an accredited third-party auditor."
                ),
            },
            "verified_chain": entries,
        }
        result = json.dumps(bundle, indent=2)
        if output_path:
            with open(output_path, "w") as f:
                f.write(result)
            print(f"[SAFE HARBOR] Proof bundle exported: {output_path}")
        return result
