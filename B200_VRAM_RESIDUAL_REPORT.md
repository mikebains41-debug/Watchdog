# B200 VRAM Residual Report

Platform: NVIDIA B200 SXM (device 0), rented via RunPod
Date: 2026-07-30
Framed identically to the existing H200 finding in README.md -- same method,
same honest limits stated up front.

---

## The finding, stated plainly

GPU memory remains reported as allocated after a process exits. This is an
accounting residual, not a data leak. Both graceful exit and SIGKILL were tested,
independently, with real byte-level pattern verification -- and in both cases, zero
bytes of the original data were recoverable.

This is the second architecture (after H200) where this exact result has been
reproduced.

---

## Method

Same methodology as the original H200 test, validation_results/cross_tenant_vram_full_methodology.py
(graceful exit) and cross_tenant_vram_sigkill_full_methodology.py (SIGKILL):

1. A process writes a known bit pattern into an 8000x8000 int32 buffer (~256MB) and
   holds it.
2. The process is ended -- once gracefully, once via SIGKILL, as two separate runs.
3. A fresh buffer is allocated in the same space and read at 10Hz for 240 seconds
   straight, checking every sample for the original pattern.

## Results

Graceful exit -- 0 bytes recovered (sustained across all samples) -- accounting residual ~1520MB -- source: vram_residual_b200_1.txt (commit bd4bcad)
SIGKILL -- 0 bytes recovered (sustained across all samples) -- accounting residual ~1520MB, identical -- source: vram_residual_sigkill_b200_1.txt (commit 75927b6)

Every single check across both 240-second runs reported matches=0 nonzero=0. Not
"mostly zero" -- zero, every sample, both exit paths.

## What this settles

The H200 evidence left one question open (recorded in EVIDENCE.md and TODO.md):
does SIGKILL clear the accounting residual differently than a graceful exit? Both
B200 exit paths produced the identical accounting figure (~1520MB), answering
this directly: the residual is exit-path independent. It is not something a
process can avoid by how it terminates, and it is not something SIGKILL happens to
fix.

## What this finding is, and is not

It IS: a real, reproducible discrepancy between what the GPU's memory-usage
counter reports and what memory is actually in use. This is a legitimate monitoring
and billing-accuracy gap -- a customer could plausibly be billed, or a capacity
planner misled, based on a number that doesn't reflect real occupied memory.

It is NOT: evidence that a previous tenant's data, weights, or code are
recoverable by the next renter of that GPU. This was tested directly, deliberately,
and repeatedly -- and the result was zero recovery every time. Any claim that this
finding demonstrates a data leak between tenants is contradicted by this project's
own evidence and should not be made.

## Separate, real finding: leftover tenant files

The genuine "data left behind for the next customer" evidence in this project is a
different result on a different layer -- actual files found in shared disk storage
(/tmp, /var/tmp), not GPU memory:

H200 / Vast.ai: files belonging to a previous tenant, 16 days old, confirmed
across 5 separate rented instances. Contents deliberately never inspected.
(README.md, EVIDENCE.md)

B200 / RunPod: the same scan run twice this session (audit_b200_1.json,
tenant_files_b200_2.json) -- both came back clean, no foreign-owned files found.

This is a genuine two-provider comparison (5-for-5 dirty on Vast.ai vs 2-for-2 clean
on RunPod), though the RunPod sample size is smaller and should not yet be treated as
a settled conclusion about that provider. This is the finding that actually supports
a "data left behind" claim -- the VRAM residual finding above does not, and the two
should never be conflated in any external-facing document.
