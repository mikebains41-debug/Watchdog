# Author: Manmohan (Mike) Bains -- Watchdog AIDR
"""
Watchdog AIDR v2.0 - Immutable Cryptographic Audit Ledger
Append-only local ledger for compliance evidence reports and alerts.
Each entry is SHA256 chained to the previous entry — any tampering
breaks the chain and is immediately detectable.
No cloud dependency. Works air-gapped.

FIXED: _get_seq() previously re-read and counted every line in the
ledger file on every single append() call -- fine for a handful of
entries, but O(n) per append means O(n^2) total cost as the ledger
grows across a long-running session. Now the sequence number is read
from the file once at startup and incremented in memory afterward.

STILL UNRESOLVED, stated rather than hidden: no file locking. If more
than one process or thread ever calls append() on the same ledger
file concurrently (e.g. a future scenario where the API thread and
the main telemetry loop both emit alerts to the same ledger instance
vs. separate instances), two writers could read the same prev_hash
and each write an entry pointing to it -- silently breaking the
single-chain assumption verify_chain() relies on. Not addressed here;
needs real file locking (e.g. fcntl) before this ledger is safe for
genuinely concurrent writers, not just sequential single-process use.

ALSO UNRESOLVED: this ledger's trust root is the local file itself.
Nothing here prevents an attacker with root on the box from deleting
the file and starting a fresh, equally "CHAIN_VALID" fake chain --
verify_chain() only proves internal consistency, not that THIS is the
original chain. Closing that gap needs external anchoring (the same
role Serial Alice's TEE attestation + Polygon anchoring already plays
for the certificates elsewhere in this project), not implemented here.
"""
import json, hashlib, time, os
from datetime import datetime, timezone

LEDGER_FILE = os.environ.get("WATCHDOG_LEDGER", "watchdog_data/audit_ledger.jsonl")

class AuditLedger:
    def __init__(self, ledger_path=None):
        self.path = ledger_path or LEDGER_FILE
        os.makedirs(os.path.dirname(self.path) if os.path.dirname(self.path) else ".", exist_ok=True)
        self._last_hash, self._next_seq = self._read_tail_state()

    def _hash_entry(self, entry_str):
        return hashlib.sha256(entry_str.encode()).hexdigest()

    def _read_tail_state(self):
        if not os.path.exists(self.path):
            return "GENESIS", 1
        last_line = None
        count = 0
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
                    count += 1
        if last_line is None:
            return "GENESIS", 1
        try:
            entry = json.loads(last_line)
            return entry.get("entry_hash", "GENESIS"), count + 1
        except Exception:
            return "GENESIS", count + 1

    def append(self, record_type, payload):
        entry = {
            "seq": self._next_seq,
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
        self._next_seq += 1
        return entry["entry_hash"]

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
