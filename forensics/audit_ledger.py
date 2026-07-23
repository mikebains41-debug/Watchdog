# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
Watchdog AIDR v2.0 - Immutable Cryptographic Audit Ledger
Append-only local ledger for compliance evidence reports and alerts.
Each entry is SHA256 chained to the previous entry — any tampering
breaks the chain and is immediately detectable.
No cloud dependency. Works air-gapped.
"""
import json, hashlib, time, os
from datetime import datetime, timezone

LEDGER_FILE = os.environ.get("WATCHDOG_LEDGER", "watchdog_data/audit_ledger.jsonl")

class AuditLedger:
    def __init__(self, ledger_path=None):
        self.path = ledger_path or LEDGER_FILE
        os.makedirs(os.path.dirname(self.path) if os.path.dirname(self.path) else ".", exist_ok=True)
        self._last_hash = self._get_last_hash()

    def _hash_entry(self, entry_str):
        return hashlib.sha256(entry_str.encode()).hexdigest()

    def _get_last_hash(self):
        if not os.path.exists(self.path):
            return "GENESIS"
        try:
            last_line = None
            with open(self.path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
            if last_line:
                entry = json.loads(last_line)
                return entry.get("entry_hash", "GENESIS")
        except Exception:
            pass
        return "GENESIS"

    def append(self, record_type, payload):
        entry = {
            "seq": self._get_seq(),
            "record_type": record_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prev_hash": self._last_hash,
            "payload": payload,
        }
        entry_str = json.dumps(entry, sort_keys=True)
        entry["entry_hash"] = self._hash_entry(entry_str)
        line = json.dumps(entry)
        with open(self.path, "a") as f:
            f.write(line + "\n")
        self._last_hash = entry["entry_hash"]
        return entry["entry_hash"]

    def _get_seq(self):
        if not os.path.exists(self.path):
            return 1
        count = 0
        with open(self.path) as f:
            for line in f:
                if line.strip():
                    count += 1
        return count + 1

    def verify_chain(self):
        if not os.path.exists(self.path):
            return True, "EMPTY_LEDGER"
        entries = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        if not entries:
            return True, "EMPTY_LEDGER"
        prev = "GENESIS"
        for i, entry in enumerate(entries):
            stored_hash = entry.pop("entry_hash")
            computed = hashlib.sha256(
                json.dumps(entry, sort_keys=True).encode()
            ).hexdigest()
            entry["entry_hash"] = stored_hash
            if entry["prev_hash"] != prev:
                return False, f"CHAIN_BREAK at seq {entry['seq']}: prev_hash mismatch"
            if stored_hash != computed:
                return False, f"TAMPER_DETECTED at seq {entry['seq']}: hash mismatch"
            prev = stored_hash
        return True, f"CHAIN_VALID — {len(entries)} entries verified"

    def get_entries(self, record_type=None, limit=100):
        if not os.path.exists(self.path):
            return []
        entries = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    e = json.loads(line)
                    if record_type is None or e.get("record_type") == record_type:
                        entries.append(e)
        return entries[-limit:]
