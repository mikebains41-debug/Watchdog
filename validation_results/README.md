# Watchdog Validation Results - Master Index

Session: Vast.ai 2x H200, 2026-06-21
All scripts paired with their actual raw output logs - every claim
here is traceable to a saved file in this folder.

## Test Categories

1. **VRAM Full Rigor** (4 tests) - memory residual at true 10Hz, sustained observation
2. **Cross-Tenant A/B PoC** (2 variants) - genuinely separate processes
3. **Watchdog Detector Validation** (2 detectors) - cache-timing, memory-attacks
4. **Contention Benchmark** (1 test) - quantified real performance impact
5. **Host Isolation Audit** (separate subfolder) - 19 files, container/host boundary checks

See SUMMARY.md for per-test results and what this means for Watchdog
as a product.
