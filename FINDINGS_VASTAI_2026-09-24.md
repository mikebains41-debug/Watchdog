# Findings — Vast.ai H200 tenant residue at handover

**Date:** 2026-09-24 (captured 01:39:54 UTC)
**Provider:** Vast.ai
**Machine:** 1x H200 (host `dfa5e32169cd`, instance 52332336, datacenter 214845)
**GPU at capture:** idle — 0% util, 0 MiB used, 74.38 W, ECC 0/0
**Method:** `scripts/handover_capture.py`, run as the first command on the rented
instance, before any workload. Open-source; reproducible by anyone.
**Evidence:** `handover_dfa5e32169cd_20260924_013954.json` (committed alongside this file).

---

## What this is

A follow-up to the June 2026 finding that Vast.ai H200 instances were handed over
without wiping the previous tenant's files (5 of 5 machines dirty). This checks
whether that is still true three months later, and adds a check June did not run.

**Sample size: 1 machine.** This confirms the problem still occurs; it does not
establish a rate. June's 5-of-5 remains the stronger sample. A 10-20 machine
sweep is the next step to turn "it still happens" into "it happens on X% of
machines."

---

## Finding 1 — Previous tenant's files present and readable (repeat of June)

The scan found 10 non-root files (of 1188 scanned). Seven are genuine base-image
defaults (`.bash_logout`, `.bashrc`, `.profile` under `/home/ubuntu` and
`/home/user`, all dated 2024-03-31, 906 days old) and are correctly excluded by
the scan as `likely_image_default: true`.

That leaves 4 files that are not image defaults. One of those
(`/root/onstart.sh`, 13 B, owned by uid 116) is Vast.ai's own provisioning
script, not a tenant artifact, so it is set aside too.

**Attributable to a previous tenant: 3 files, of which 1 carries content:**

| Path | Owner | Size | Age at handover | Content? |
|---|---|---|---|---|
| `/home/user/.condarc` | user (uid 1001) | 273 B | **16.4 days** (2026-09-07) | yes |
| `/home/user/.ssh/authorized_keys` | user (uid 1001) | 0 B | 0.0 days | empty |
| `/home/ubuntu/.ssh/authorized_keys` | ubuntu (uid 1000) | 0 B | 0.0 days | empty |

`/home/user/.bashrc` (4896 B, 0.0 days) is also present and larger than the
default, but its 0-day age means it cannot be dated to a prior tenant with
certainty, so it is not counted as proof.

**The decisive item:** `/home/user/.condarc`, 273 bytes, last modified
**2026-09-07 — 16 days before this rental began.** It cannot be from this session
and is not a base-image file. It is a previous tenant's file, present and readable
by the incoming renter. That single file is sufficient to prove the machine was
not wiped between tenants.

---

## Finding 2 — GPU activity counters not reset (new; June did not check this)

NVLink is active (`available: true`, 36 counters = 18 links x Tx+Rx). The counters
were handed over carrying the previous tenant's cumulative traffic:

- **Total: 1,065,509,220,356 KiB = approx 1.09 petabytes**, across all 36 counters.
- Each link shows ~29.5-29.9 billion KiB in each direction — consistent, heavy
  multi-GPU use by whoever held the machine before this rental.

These are not reset to zero between tenants. The incoming renter is handed a
detailed record of the previous tenant's GPU interconnect activity. June did not
test this; it is a new finding.

---

## What is proven — and what is deliberately NOT

**Proven:** the provider handed over a machine containing a previous tenant's file
(`.condarc`, 16 days old) and un-reset GPU activity counters (~1.09 PB of prior
traffic), both readable by the next renter. The provider failed to wipe the
machine between tenants.

**Deliberately not done:** the scan recorded only metadata — each file's path,
size, owner, timestamp, mode. It did NOT open, read, copy, or hash the contents of
any file. This is the ethical and legal boundary the method is built on:

1. **Legality.** Reading another tenant's file contents could be unauthorized
   access to their data — the very wrong being reported. Observing that a file
   exists and is readable is a statement about the provider's hygiene; opening it
   would be an intrusion on the other tenant.
2. **Credibility.** The claim is precise and defensible — "the provider fails to
   wipe machines between tenants" — not the unprovable, self-incriminating "I read
   another customer's data." The former is reproducible by anyone; the latter
   would put the researcher in the wrong.
3. **Sufficiency.** Proving data is left behind and readable is a complete
   finding. The exposure is the provider's failure. Whether an attacker then reads
   it is a separate act; the defect already exists.

**Exact claim:** "Vast.ai handed over a machine containing a previous tenant's
file (16 days old) and GPU activity counters showing ~1 PB of prior traffic, both
readable by the next renter. The provider failed to wipe the machine between
tenants. No tenant data was opened or exfiltrated in demonstrating this."

---

## Disclosure history

- **June 2026:** the unpatched-kernel finding on Vast.ai H200 was reported to
  security@vast.ai. No response received. The leftover-files finding was not
  separately reported at that time.
- **2026-09-24:** this result. Not yet reported.

## Limits, stated plainly

- One machine (n=1). Confirms recurrence, not rate.
- Single operator, no third-party audit.
- Metadata only; contents never inspected, so "readable" is demonstrated by
  ownership and permissions, not by reading.
- `.bashrc` present but not counted as proof (0-day age); only `.condarc`
  (16 days) is dated to a prior tenant with certainty.
