# Critical Findings - Vast.ai 2x H200 Instance 41986069
Date: 2026-06-21 / 2026-06-22
Researcher: Manmohan (Mike) Bains
Project: GPU Optimizer / Watchdog

## Finding 1: Unpatched Kernel CVE-2026-31431 (CRITICAL - CVSS 7.8)
Kernel: Linux 5.15.0-140-generic (built April 2025)
CVE: CVE-2026-31431 "Copy Fail" - container escape via shared page cache
Confirmed: cat /proc/version
Live-patch check: No live-patch tools found - confirmed unpatched
Status: NOT exploited - version check only
Action: Responsible disclosure to security@vast.ai

## Finding 2: Container Overlay Layer Retains Previous Tenant Files (MEDIUM)
Files dated 2026-06-05 14:43 still present on 2026-06-22 - 17 days old.
findmnt /tmp: no output - /tmp uses container overlay filesystem directly.
Framing: container overlay layer retains files from a previous tenant
session. Not a host-shared /tmp mount gap but an overlay sanitization gap.

Raw evidence (5 independent confirmations):
- tmp3j31amsg_kernels/ (empty directory, drwx------)
- tmp5viu561v_kernels/ (empty directory, drwx------)
- tmpap3y5yro_kernels/ (empty directory, drwx------)
- uv-e147f089dc971b1b.lock (0 bytes, -rw-rw-rw-)

Contents: NOT inspected

## Finding 3: -9.5% Noisy-Neighbor Performance Impact (LOW/MEDIUM)
Baseline: 372.32 iter/sec
Under contention: 336.96 iter/sec
Framing: noisy-neighbor performance degradation, not isolation failure.

## Key Point
Neither Finding 1 nor Finding 2 visible to GPU Optimizer (GPU telemetry
only). Both required Watchdog host/OS-level checks - validates Watchdog
as a separate, essential security layer alongside GPU Optimizer.
