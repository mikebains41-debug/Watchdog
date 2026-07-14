# compliance_evidence_test.py

**Author:** Manmohan (Mike) Bains
**Status:** Working, tested live on this device (2/2 passed)
**Corrected:** original version called methods (get_chain,
export_evidence) that do not exist in the real AuditLedger class --
rewritten to match the actual, confirmed API.

## What This Is

Proves the real forensics/audit_ledger.py tamper-evident hash chain
works correctly, using the actual confirmed methods: append(record_type,
payload), verify_chain(), get_entries().

## What It Actually Checks

1. Writes 10 test entries to the ledger via the real append() method
2. Calls the real verify_chain() method to confirm hash-chain integrity
3. Retrieves entries back via get_entries() to confirm they are
   readable after being written

## Why It Matters

A tamper-evident audit log is a real requirement for SOC2 and similar
compliance frameworks -- this test proves the mechanism genuinely
works (entries are hash-chained and verifiably unaltered), not just
that it runs without crashing.

## Honest Note

The original pasted test also referenced a ComplianceReportGenerator
class for SOC2/EU AI Act mapping. That class's real method signatures
were not verified in this session -- that portion was removed rather
than guessed at again. Worth checking forensics/compliance_report.py's
real API separately before adding that test back.

## Confirmed Run Result (this device)

2/2 passed: audit ledger chain valid, 10 entries successfully retrieved.

## How To Run

python3 tests/compliance_evidence_test.py
