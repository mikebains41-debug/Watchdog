# Author: Manmohan (Mike) Bains -- Watchdog
"""
Watchdog v2.0 - Immutable Cryptographic Audit Ledger
Append-only local ledger for compliance evidence reports and alerts.
Each entry is SHA256 chained to the previous entry — any tampering
breaks the chain and is immediately detectable.
No cloud dependency by default. External anchoring (see anchor())
is opt-in and uses email, not a blockchain or any paid service.

FIXED (this pass): the two limitations disclosed in the previous
version are now addressed.

1. FILE LOCKING. append() now acquires an exclusive fcntl lock around
   the ENTIRE read-tail-state + write sequence, not just the write.
   This matters: a lock around the write alone is not sufficient if
   the last_hash/seq used to build the new entry came from a stale
   in-memory cache -- two concurrent writers could each compute an
   entry pointing at the same prev_hash and fork the chain without
   ever technically violating a lock on the write itself. Correctness
   requires re-reading the actual last entry from disk INSIDE the
   lock, immediately before computing the new one.

   HONEST TRADEOFF: this reintroduces a real file read on every
   append(), which the previous fix specifically removed for
   performance. Given this ledger's actual expected volume (alert
   counts per session, not a high-frequency trading log), correctness
   under concurrent writers was judged worth more than the raw speed
   of the in-memory-cache-only version. If Watchdog's alert volume
   ever grows enough for this to matter, revisit with an indexed tail
   read rather than reverting to an unsafe cache.

   fcntl.flock is POSIX advisory locking -- it only protects against
   OTHER PROCESSES/THREADS THAT ALSO USE flock ON THIS SAME FILE. It
   does not prevent a process that ignores locking entirely from
   writing to the file. This has only been tested in this sandbox, not
   on the actual Termux/Android target -- fcntl is standard POSIX and
   Termux is a real Linux userland, but this specific behavior has not
   been confirmed on that real device yet.

2. EXTERNAL ANCHORING. anchor() sends the current chain's tail hash,
   entry count, and timestamp via EmailAlerter to an external inbox.
   This is NOT equivalent to Serial Alice's blockchain anchoring
   elsewhere in this project, and this file does not pretend it is:
   a blockchain anchor is publicly, independently verifiable by
   anyone; an emailed hash is only as trustworthy as that one inbox,
   and compromising it is a single point of failure this design does
   not eliminate, only relocates. What it DOES provide: an attacker
   with full root access to THIS machine, who deletes the ledger file
   and starts a fresh, internally-"valid" fake chain, cannot make that
   fake chain match a hash that was already recorded somewhere they
   don't control. That is a real, meaningful property -- just a
   weaker one than a public blockchain anchor, stated as such rather
   than oversold.

   Anchoring is NOT automatic on every append() -- that would defeat
   the "no cloud dependency by default" design and spam the inbox.
   Call anchor() explicitly (e.g. periodically, or at shutdown) with a
   configured EmailAlerter.
"""
import json, hashlib, time, os
import fcntl
from datetime import datetime, timezone

LEDGER_FILE = os.environ.get("WATCHDOG_LEDGER", "watchdog_data/audit_ledger.jsonl")

class AuditLedger:
    def __init__(self, ledger_path=None, email_alerter=None):
        self.path = ledger_path or LEDGER_FILE
        os.makedirs(os.path.dirname(self.path) if os.path.dirname(self.path) else ".", exist_ok=True)
        self.email_alerter = email_alerter
        self._last_anchor_seq = 0

    def _hash_entry(self, entry_str):
        return hashlib.sha256(entry_str.encode()).hexdigest()

    def _read_tail_state_unlocked(self):
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
        with open(self.path, "a") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                last_hash, next_seq = self._read_tail_state_unlocked()
                entry = {
                    "seq": next_seq,
                    "record_type": record_type,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "prev_hash": last_hash,
                    "payload": payload,
                }
                entry_str = json.dumps(entry, sort_keys=True)
                entry["entry_hash"] = self._hash_entry(entry_str)
                line = json.dumps(entry)
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
                return entry["entry_hash"]
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

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

    def anchor(self, force=False):
        if self.email_alerter is None:
            return False

        entries = self.get_entries(limit=1)
        if not entries:
            return False

        latest = entries[-1]
        if not force and latest["seq"] == self._last_anchor_seq:
            return False

        anchor_alert = {
            "type": "AUDIT_LEDGER_ANCHOR",
            "severity": "INFO",
            "gpu": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": (f"Audit ledger anchor: {latest['seq']} entries, "
                        f"tail hash {latest['entry_hash'][:16]}... "
                        f"(external record only -- not a blockchain "
                        f"anchor, see AuditLedger's module docstring "
                        f"for the real, weaker guarantee this provides)"),
        }
        sent = self.email_alerter.send(anchor_alert)
        if sent:
            self._last_anchor_seq = latest["seq"]
        return sent
