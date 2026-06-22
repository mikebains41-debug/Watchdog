# Critical Findings - Vast.ai 2x H200 Instance 41986069
Date: 2026-06-21 / 2026-06-22
Researcher: Manmohan (Mike) Bains
Project: GPU Optimizer / Watchdog

## Finding 1: Unpatched Kernel CVE-2026-31431 (CRITICAL - CVSS 7.8)
Kernel: Linux 5.15.0-140-generic (built April 2025)
CVE: CVE-2026-31431 "Copy Fail" - container escape via shared page cache
Confirmed: cat /proc/version
Status: NOT exploited - version check only
Action: Responsible disclosure to security@vast.ai

## Finding 2: Shared /tmp Storage Residual (MEDIUM)
Files dated 2026-06-05 14:43 found on 2026-06-21 and confirmed again
on 2026-06-22 - 17 days before/after rental start.

Raw evidence (5 independent confirmations):
- tmp3j31amsg_kernels/ (empty directory, drwx------)
- tmp5viu561v_kernels/ (empty directory, drwx------)
- tmpap3y5yro_kernels/ (empty directory, drwx------)
- uv-e147f089dc971b1b.lock (0 bytes, -rw-rw-rw-)

All timestamped: Jun 5 14:43
Container start confirmed: Jun 22 02:30 (/dev/shm timestamp)
Days predating rental: 17

Contents: NOT inspected (unauthorized access avoided)
Directories confirmed empty via ls -la inside each

Command used: ls -la /dev/shm /tmp

## Finding 3: -9.5% Contention Throughput Drop (LOW/MEDIUM)
Baseline: 372.32 iter/sec
Under contention: 336.96 iter/sec
Script: contention_benchmark.py

## Key Point
Neither Finding 1 nor Finding 2 would have been detected by GPU
Optimizer (GPU telemetry only). Both required Watchdog's host/OS-level
checks. This validates Watchdog as a separate, essential security layer.
