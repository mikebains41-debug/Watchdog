#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
# Watchdog - Compliance Evidence Generation Test
# Proves the real AuditLedger append/verify chain works correctly.
#
# CORRECTED: the original pasted version of this test called
# ledger.append(dict) and ledger.get_chain()/export_evidence(), which
# do not exist in the real forensics/audit_ledger.py. This version
# uses the actual, confirmed method signatures: append(record_type,
# payload), verify_chain(), get_entries().

import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from forensics.audit_ledger import AuditLedger


class ComplianceEvidenceTest:
    def __init__(self):
        self.results = {}

    def test_audit_ledger(self):
        ledger = AuditLedger(ledger_path="test_audit_ledger.jsonl")
        for i in range(10):
            ledger.append("test_event", {"index": i, "timestamp": datetime.now().isoformat()})
        valid = ledger.verify_chain()
        self.results['audit_ledger_chain_valid'] = bool(valid)
        print(f"AuditLedger chain: {'VALID' if valid else 'BROKEN'}")

    def test_get_entries(self):
        ledger = AuditLedger(ledger_path="test_audit_ledger.jsonl")
        entries = ledger.get_entries(record_type="test_event", limit=10)
        self.results['entries_retrievable'] = len(entries) > 0
        print(f"Retrieved {len(entries)} entries from ledger")

    def run(self):
        print("Compliance Evidence Generation Test (corrected to match real AuditLedger API)")
        print("-" * 60)
        self.test_audit_ledger()
        self.test_get_entries()
        print("-" * 60)
        passes = sum(self.results.values())
        total = len(self.results)
        print(f"Compliance Tests: {passes}/{total} passed")
        with open("compliance_results.json", "w") as f:
            json.dump(self.results, f, indent=2)
        return passes == total


if __name__ == "__main__":
    test = ComplianceEvidenceTest()
    success = test.run()
    sys.exit(0 if success else 1)
